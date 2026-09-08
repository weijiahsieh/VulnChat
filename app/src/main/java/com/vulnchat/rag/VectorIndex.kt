package com.vulnchat.rag

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * VectorIndex — in-memory store and similarity search over embedded chunks.
 *
 * Deliberately not persisted, for the same reason ConversationRepository
 * isn't: an on-device vector database is a recoverable artifact. Indexed
 * document text sits in it in plaintext, and `adb backup` or root file
 * access retrieves the whole corpus. Keeping the index in memory means it
 * dies with the process. The cost is re-indexing on every launch, which is
 * acceptable for a demo corpus and is the right default for sensitive
 * documents even in production.
 *
 * For a production app that genuinely needs persistence, the answer is
 * SQLCipher-backed storage with the key in Android Keystore — the same
 * pattern ApiKeyProvider already implements.
 *
 * THREAD SAFETY
 *   Ingestion happens on a background coroutine while the UI may be reading
 *   [documentCount]. A Mutex guards mutation; searches read a snapshot of
 *   the list, so a search in flight is never disturbed by a concurrent add.
 */
class VectorIndex(private val expectedDimensions: Int) {

    private val mutex = Mutex()
    private val chunks = mutableListOf<RagChunk>()

    private val _documentCount = MutableStateFlow(0)
    val documentCount: StateFlow<Int> = _documentCount.asStateFlow()

    private val _chunkCount = MutableStateFlow(0)
    val chunkCount: StateFlow<Int> = _chunkCount.asStateFlow()

    // ─────────────────────────────────────────────────────────────────
    // Mutation
    // ─────────────────────────────────────────────────────────────────

    /**
     * Adds chunks to the index.
     *
     * Rejects any chunk whose embedding is absent or the wrong length.
     * A dimension mismatch means the chunk was embedded by a different
     * provider than the one currently configured — silently indexing it
     * would produce meaningless similarity scores that look plausible,
     * which is worse than an error.
     */
    suspend fun add(newChunks: List<RagChunk>) = mutex.withLock {
        for (chunk in newChunks) {
            val embedding = chunk.embedding
            require(embedding != null) {
                "Chunk ${chunk.id} has no embedding — embed before indexing"
            }
            require(embedding.size == expectedDimensions) {
                "Chunk ${chunk.id} has ${embedding.size} dimensions, " +
                "index expects $expectedDimensions"
            }
        }
        chunks += newChunks
        recount()
    }

    /** Removes every chunk belonging to a document. */
    suspend fun removeDocument(documentId: String) = mutex.withLock {
        chunks.removeAll { it.documentId == documentId }
        recount()
    }

    suspend fun clear() = mutex.withLock {
        chunks.clear()
        recount()
    }

    private fun recount() {
        _chunkCount.value = chunks.size
        _documentCount.value = chunks.map { it.documentId }.distinct().size
    }

    // ─────────────────────────────────────────────────────────────────
    // Search
    // ─────────────────────────────────────────────────────────────────

    /**
     * Returns the [topK] most similar chunks above [minScore].
     *
     * TRUST-WEIGHTED SCORING
     *   An untrusted chunk's score is multiplied by [UNTRUSTED_PENALTY]
     *   before ranking. The effect is that third-party content must be
     *   meaningfully *more* relevant than trusted content to earn a slot in
     *   the context, rather than merely competitive with it.
     *
     *   This matters because retrieval is itself an attack surface: an
     *   attacker who controls a document can pad it to match a wide range of
     *   queries, and without a penalty their chunk wins slots against
     *   legitimate material on equal terms. The penalty does not stop the
     *   attack — DocumentSanitizer and ContextBuilder do that — but it
     *   raises the cost of getting retrieved in the first place.
     *
     * PER-DOCUMENT CAP
     *   [maxPerDocument] limits how many slots any single document can take.
     *   Without it, one poisoned document that matches the query well can
     *   fill every slot and crowd out all legitimate context. This is the
     *   single most valuable control in this method: it converts "one bad
     *   document owns the entire context" into "one bad document gets one
     *   slot alongside genuine sources".
     */
    suspend fun search(
        queryEmbedding: FloatArray,
        topK: Int = DEFAULT_TOP_K,
        minScore: Float = DEFAULT_MIN_SCORE,
        maxPerDocument: Int = DEFAULT_MAX_PER_DOCUMENT
    ): List<ScoredChunk> = withContext(Dispatchers.Default) {

        require(queryEmbedding.size == expectedDimensions) {
            "Query has ${queryEmbedding.size} dimensions, index expects $expectedDimensions"
        }

        // Snapshot under lock, then score outside it — scoring is the
        // expensive part and holding the lock through it would block ingestion.
        val snapshot = mutex.withLock { chunks.toList() }
        if (snapshot.isEmpty()) return@withContext emptyList()

        val scored = snapshot.mapNotNull { chunk ->
            val embedding = chunk.embedding ?: return@mapNotNull null
            val raw = cosineSimilarity(queryEmbedding, embedding)
            val adjusted = raw * trustMultiplier(chunk.trustLevel)
            if (adjusted < minScore) null else ScoredChunk(chunk, adjusted)
        }

        // Rank, then apply the per-document cap while walking the ranked list
        // so the highest-scoring chunk from each document is kept first.
        val perDocument = mutableMapOf<String, Int>()
        val result = mutableListOf<ScoredChunk>()

        for (candidate in scored.sortedByDescending { it.score }) {
            val docId = candidate.chunk.documentId
            val used = perDocument[docId] ?: 0
            if (used >= maxPerDocument) continue

            result += candidate
            perDocument[docId] = used + 1
            if (result.size >= topK) break
        }

        result
    }

    private fun trustMultiplier(level: TrustLevel): Float = when (level) {
        TrustLevel.TRUSTED -> 1.0f
        TrustLevel.USER -> 1.0f
        TrustLevel.UNTRUSTED -> UNTRUSTED_PENALTY
    }

    /**
     * Cosine similarity.
     *
     * Both providers L2-normalise their output, so this reduces to a dot
     * product — but the norms are recomputed rather than assumed. Assuming
     * normalisation is the kind of invariant that holds until someone
     * implements a third provider and forgets, and the failure would be
     * silent: scores would still be numbers, just wrong ones.
     */
    private fun cosineSimilarity(a: FloatArray, b: FloatArray): Float {
        var dot = 0f
        var normA = 0f
        var normB = 0f

        for (i in a.indices) {
            dot += a[i] * b[i]
            normA += a[i] * a[i]
            normB += b[i] * b[i]
        }

        if (normA == 0f || normB == 0f) return 0f
        return dot / (kotlin.math.sqrt(normA) * kotlin.math.sqrt(normB))
    }

    private companion object {
        const val DEFAULT_TOP_K = 5
        const val DEFAULT_MAX_PER_DOCUMENT = 2

        /**
         * Chunks below this adjusted score are never retrieved. A low
         * threshold pulls in marginally-relevant text, which both wastes
         * context and widens the set of documents an attacker can get
         * retrieved with an arbitrary query.
         */
        const val DEFAULT_MIN_SCORE = 0.12f

        /** Untrusted chunks must clear a higher bar to be retrieved. */
        const val UNTRUSTED_PENALTY = 0.75f
    }
}
