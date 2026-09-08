package com.vulnchat.rag

import android.util.Log
import com.vulnchat.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.math.ln
import kotlin.math.sqrt

/**
 * EmbeddingProvider — converts text into a vector for similarity search.
 *
 * THE SECURITY QUESTION THIS LAYER ANSWERS
 *
 * Embedding is the step where RAG quietly leaks. To index a document you
 * must first send its full text somewhere to be vectorised. If that
 * "somewhere" is a third-party embedding API, then every document the user
 * indexes — their notes, contracts, medical records, whatever they dropped
 * into the app — is transmitted off-device to a vendor who was never named
 * in the app's privacy policy.
 *
 * This is a real and under-discussed RAG risk. It is not a prompt injection
 * problem, it is a data governance problem, and it is invisible to the user
 * because indexing happens in the background with no visible network activity.
 *
 * TWO IMPLEMENTATIONS, DELIBERATELY CONTRASTED:
 *
 *   [OnDeviceEmbeddingProvider]  — nothing leaves the device. No second API
 *     key to protect, no vendor relationship, no egress. Retrieval quality is
 *     lower than a neural embedding, which is the honest trade-off.
 *
 *   [RemoteEmbeddingProvider]    — better retrieval quality, at the cost of
 *     shipping every document to a third party and introducing a second
 *     credential with the same extraction problem as the main API key.
 *
 * The hardened build uses on-device. The vulnerable build uses remote, so
 * the demo can show document contents leaving the device in MitmProxy.
 *
 * Portfolio interview point:
 *   "Where does your embedding happen?" is a question most RAG candidates
 *   have not considered. Being able to answer it — and to explain why you
 *   chose lower retrieval quality in exchange for keeping user documents
 *   on-device — demonstrates that you treated RAG as a data-flow problem,
 *   not just a retrieval-quality problem.
 */
interface EmbeddingProvider {

    /** Dimensionality of vectors produced. Must be stable for an index. */
    val dimensions: Int

    /** Human-readable identifier, surfaced in the UI so the user knows. */
    val displayName: String

    /** True when text is transmitted off-device to produce the vector. */
    val transmitsOffDevice: Boolean

    /**
     * Embeds a single text. Suspending because the remote implementation
     * performs network I/O; the on-device one still runs off the main thread.
     */
    suspend fun embed(text: String): FloatArray

    /**
     * Embeds many texts. Default implementation is sequential; the remote
     * provider overrides this to batch, which matters both for latency and
     * for reducing the number of requests carrying document text.
     */
    suspend fun embedAll(texts: List<String>): List<FloatArray> =
        texts.map { embed(it) }

    companion object {
        /**
         * Selects the provider for the current build.
         *
         * Hardened builds are on-device unconditionally — this is not a
         * configurable preference, because a settings toggle that silently
         * starts transmitting documents is exactly the failure mode this
         * layer exists to prevent.
         */
        fun forCurrentBuild(): EmbeddingProvider =
            if (BuildConfig.SECURE_MODE) OnDeviceEmbeddingProvider()
            else RemoteEmbeddingProvider()
    }
}

// ─────────────────────────────────────────────────────────────────────
// On-device — hashed n-gram embedding
// ─────────────────────────────────────────────────────────────────────

/**
 * Produces vectors entirely on-device using the hashing trick over character
 * and word n-grams, with sublinear term weighting.
 *
 * HOW IT WORKS
 *   1. Normalise and tokenise the text into word unigrams, word bigrams, and
 *      character 4-grams. Character n-grams give robustness to typos and
 *      morphology that word tokens alone do not.
 *   2. Hash each feature into one of [DIMENSIONS] buckets. No vocabulary is
 *      stored, so the index never has to be rebuilt when new terms appear.
 *   3. Weight each bucket by 1 + ln(count) — sublinear, so a term repeated
 *      forty times does not dominate the vector. This also blunts a crude
 *      retrieval-poisoning technique where an attacker pads a document with
 *      repeated keywords to make it match everything.
 *   4. L2-normalise so cosine similarity reduces to a dot product.
 *
 * HONEST LIMITATIONS
 *   This is lexical, not semantic. "car" and "automobile" hash to unrelated
 *   buckets and will not match. For a production app, bundle a quantised
 *   sentence-transformer as a TFLite asset and implement this interface
 *   against it — the rest of the pipeline needs no changes, which is the
 *   point of putting an interface here.
 *
 *   That swap is also the natural extension of this project into on-device
 *   ML security: once a model file ships inside the APK, it becomes an asset
 *   an attacker can extract, analyse, and attack directly.
 */
class OnDeviceEmbeddingProvider : EmbeddingProvider {

    override val dimensions = DIMENSIONS
    override val displayName = "On-device (hashed n-gram)"
    override val transmitsOffDevice = false

    override suspend fun embed(text: String): FloatArray = withContext(Dispatchers.Default) {
        val counts = HashMap<Int, Int>()

        val normalised = text.lowercase().replace(NON_ALPHANUM, " ")
        val words = normalised.split(' ').filter { it.length >= MIN_TOKEN_LEN }

        // Word unigrams
        for (w in words) {
            bump(counts, bucket("w:$w"))
        }

        // Word bigrams — captures short phrases, which matters for queries
        // like "certificate pinning" where each word alone is ambiguous.
        for (i in 0 until words.size - 1) {
            bump(counts, bucket("b:${words[i]}_${words[i + 1]}"))
        }

        // Character 4-grams over the normalised text
        val compact = normalised.replace(MULTI_SPACE, " ")
        for (i in 0..compact.length - CHAR_NGRAM) {
            bump(counts, bucket("c:${compact.substring(i, i + CHAR_NGRAM)}"))
        }

        toNormalisedVector(counts)
    }

    /**
     * Maps a feature string to a bucket index.
     *
     * Uses the string's own hash mixed with a fixed seed. The seed is a
     * constant rather than random per-install: vectors must be comparable
     * across app launches, and a per-install seed would silently invalidate
     * every stored embedding on reinstall.
     */
    private fun bucket(feature: String): Int {
        var h = HASH_SEED
        for (ch in feature) {
            h = h * 31 + ch.code
            h = h xor (h ushr 15)
        }
        // and-mask instead of modulo — DIMENSIONS is a power of two, and this
        // avoids the negative-remainder trap with Int.MIN_VALUE.
        return h and (DIMENSIONS - 1)
    }

    private fun bump(counts: HashMap<Int, Int>, idx: Int) {
        counts[idx] = (counts[idx] ?: 0) + 1
    }

    /** Applies sublinear weighting then L2-normalises. */
    private fun toNormalisedVector(counts: Map<Int, Int>): FloatArray {
        val vec = FloatArray(DIMENSIONS)
        for ((idx, count) in counts) {
            vec[idx] = (1.0 + ln(count.toDouble())).toFloat()
        }

        var sumSq = 0.0
        for (v in vec) sumSq += v * v
        val norm = sqrt(sumSq).toFloat()

        // A vector of all zeros is possible for input shorter than the
        // minimum token length. Return it as-is rather than dividing by zero;
        // VectorIndex treats a zero vector as matching nothing.
        if (norm == 0f) return vec

        for (i in vec.indices) vec[i] = vec[i] / norm
        return vec
    }

    private companion object {
        /** Power of two so bucket() can use an and-mask. */
        const val DIMENSIONS = 1024
        const val HASH_SEED = 0x9E3779B9.toInt()
        const val CHAR_NGRAM = 4
        const val MIN_TOKEN_LEN = 2

        val NON_ALPHANUM = Regex("[^a-z0-9]+")
        val MULTI_SPACE = Regex("\\s+")
    }
}

// ─────────────────────────────────────────────────────────────────────
// Remote — third-party embedding API
// ─────────────────────────────────────────────────────────────────────

/**
 * Sends text to a hosted embedding API.
 *
 * Present in this project as the *vulnerable* path, and left deliberately
 * unfinished at the network level — wiring a real vendor here would mean
 * shipping a second API key in the APK, which is precisely the anti-pattern
 * the project exists to demonstrate. The stub produces a deterministic
 * vector so the pipeline runs end-to-end, and logs loudly each time it would
 * have transmitted document text.
 *
 * What the demo shows:
 *   Run the vulnerable build with MitmProxy attached, index a document, and
 *   point at the log line below. The user performed a local action — adding
 *   a file — and the full contents of that file left the device as a side
 *   effect. No consent dialog, no indication in the UI.
 *
 * To make this a live demo rather than a logged one, implement [embed]
 * against a real embeddings endpoint and add a second key to
 * secrets.properties. The extraction demo then works identically on that
 * key as on the main one, which is itself the lesson: every additional
 * credential is another thing jadx will find.
 */
class RemoteEmbeddingProvider : EmbeddingProvider {

    override val dimensions = DIMENSIONS
    override val displayName = "Remote API (transmits documents)"
    override val transmitsOffDevice = true

    private val fallback = OnDeviceEmbeddingProvider()

    override suspend fun embed(text: String): FloatArray {
        Log.w(TAG,
            "Would transmit ${text.length} chars of document text to a " +
            "third-party embedding API. Content preview: " +
            text.take(60).replace('\n', ' ')
        )
        // Deterministic stand-in so retrieval still functions in the demo.
        return fallback.embed(text)
    }

    override suspend fun embedAll(texts: List<String>): List<FloatArray> {
        Log.w(TAG, "Would transmit ${texts.size} chunks in one batch request.")
        return texts.map { embed(it) }
    }

    private companion object {
        const val TAG = "RemoteEmbedding"
        const val DIMENSIONS = 1024
    }
}
