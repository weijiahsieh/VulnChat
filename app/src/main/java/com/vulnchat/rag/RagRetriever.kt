package com.vulnchat.rag

import android.util.Log
import com.vulnchat.BuildConfig
import kotlinx.coroutines.flow.StateFlow
import java.util.UUID

/**
 * RagRetriever — the single entry point ChatViewModel talks to.
 *
 * Owns the full pipeline in both directions:
 *
 *   INGEST   document → sanitize → chunk → embed → index
 *   RETRIEVE query    → embed    → search → build context string
 *
 * Everything the ViewModel needs is here, so the security controls in
 * DocumentSanitizer, VectorIndex, and ContextBuilder cannot be bypassed by
 * a caller that reaches around them. That containment is deliberate: an
 * ingestion path that skipped sanitization would be an easy mistake to make
 * if the ViewModel wired the components together itself.
 */
class RagRetriever(
    private val embeddingProvider: EmbeddingProvider = EmbeddingProvider.forCurrentBuild(),
    private val sanitizer: DocumentSanitizer = DocumentSanitizer(),
    private val contextBuilder: ContextBuilder = ContextBuilder()
) {

    private val index = VectorIndex(embeddingProvider.dimensions)

    val documentCount: StateFlow<Int> get() = index.documentCount
    val chunkCount: StateFlow<Int> get() = index.chunkCount

    /** Surfaced in the UI so the user can see whether documents leave the device. */
    val embeddingDescription: String get() = embeddingProvider.displayName
    val embeddingTransmitsOffDevice: Boolean get() = embeddingProvider.transmitsOffDevice

    // ─────────────────────────────────────────────────────────────────
    // Ingestion
    // ─────────────────────────────────────────────────────────────────

    sealed class IngestResult {
        data class Indexed(
            val document: RagDocument,
            val chunkCount: Int,
            val report: SanitizationReport
        ) : IngestResult()

        data class Rejected(
            val document: RagDocument,
            val report: SanitizationReport
        ) : IngestResult()

        data class Failed(val cause: Throwable) : IngestResult()
    }

    /**
     * Ingests a document: sanitize, chunk, embed, index.
     *
     * Sanitization runs first and its verdict is final. On REJECTED nothing
     * is embedded and nothing is indexed — the document does not reach the
     * embedding provider at all, which also means a rejected document is
     * never transmitted off-device even on the remote-embedding path.
     */
    suspend fun ingest(
        title: String,
        content: String,
        source: String,
        trustLevel: TrustLevel = TrustLevel.UNTRUSTED
    ): IngestResult {
        return try {
            val document = RagDocument(
                id = UUID.randomUUID().toString(),
                title = title,
                content = content,
                source = source,
                trustLevel = trustLevel
            )

            val report = sanitizer.sanitize(document)
            val sanitized = document.copy(sanitizationReport = report)

            if (report.verdict == SanitizationVerdict.REJECTED) {
                Log.w(TAG, "Rejected '$title': ${report.findings.size} findings")
                return IngestResult.Rejected(sanitized, report)
            }

            // Chunk the CLEANED content, never the original. This is the
            // load-bearing line of the whole ingestion path — using
            // document.content here would silently undo sanitization.
            val texts = chunk(report.cleanedContent)
            if (texts.isEmpty()) {
                return IngestResult.Rejected(sanitized, report)
            }

            val embeddings = embeddingProvider.embedAll(texts)

            val ragChunks = texts.mapIndexed { i, text ->
                RagChunk(
                    id = "${document.id}:$i",
                    documentId = document.id,
                    sourceTitle = document.title,
                    trustLevel = document.trustLevel,
                    text = text,
                    ordinal = i,
                    embedding = embeddings[i]
                )
            }

            index.add(ragChunks)
            IngestResult.Indexed(sanitized, ragChunks.size, report)

        } catch (e: Exception) {
            Log.e(TAG, "Ingestion failed for '$title'", e)
            IngestResult.Failed(e)
        }
    }

    suspend fun removeDocument(documentId: String) = index.removeDocument(documentId)

    suspend fun clearIndex() = index.clear()

    // ─────────────────────────────────────────────────────────────────
    // Retrieval
    // ─────────────────────────────────────────────────────────────────

    data class RetrievalResult(
        /** Ready to prepend to the user's turn. Empty when nothing matched. */
        val contextBlock: String,
        val chunks: List<ScoredChunk>
    ) {
        val isEmpty: Boolean get() = contextBlock.isEmpty()
    }

    /**
     * Retrieves context for a user query.
     *
     * IMPORTANT ORDERING CONSTRAINT
     *   The caller must run InputFilter *before* calling this. A blocked
     *   query should never be embedded or used to search, for two reasons:
     *   it wastes an embedding call, and on the remote-embedding path it
     *   transmits the attacker's payload off-device. ChatViewModel enforces
     *   this ordering; it is stated here because the constraint is not
     *   visible from this method's signature.
     */
    suspend fun retrieve(query: String): RetrievalResult {
        if (index.chunkCount.value == 0) {
            return RetrievalResult("", emptyList())
        }

        return try {
            val queryEmbedding = embeddingProvider.embed(query)
            val hits = index.search(queryEmbedding)

            if (BuildConfig.DEBUG && hits.isNotEmpty()) {
                Log.d(TAG, "Retrieved ${hits.size} chunks: " +
                        hits.joinToString { "${it.chunk.sourceTitle}(${"%.2f".format(it.score)})" })
            }

            RetrievalResult(
                contextBlock = contextBuilder.build(hits),
                chunks = hits
            )
        } catch (e: Exception) {
            // Retrieval failure degrades to no context rather than failing
            // the message. The user still gets an answer, just without
            // documents — strictly better than an error for a feature that
            // is an enhancement rather than the core function.
            Log.e(TAG, "Retrieval failed", e)
            RetrievalResult("", emptyList())
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Chunking
    // ─────────────────────────────────────────────────────────────────

    /**
     * Splits text into overlapping chunks on paragraph then sentence
     * boundaries, falling back to a hard character split for text with no
     * usable boundaries at all.
     *
     * The overlap exists so a fact spanning a boundary is retrievable from
     * either side. It has a security consequence worth knowing: overlap
     * means injected text near a boundary appears in two chunks and gets two
     * chances to be retrieved. The per-document cap in VectorIndex.search is
     * what bounds that.
     */
    private fun chunk(text: String): List<String> {
        val clean = text.trim()
        if (clean.isEmpty()) return emptyList()
        if (clean.length <= MAX_CHUNK_CHARS) return listOf(clean)

        val units = clean.split(PARAGRAPH_BREAK)
            .flatMap { para ->
                if (para.length <= MAX_CHUNK_CHARS) listOf(para)
                else para.split(SENTENCE_BREAK)
            }
            .map { it.trim() }
            .filter { it.isNotEmpty() }

        val chunks = mutableListOf<String>()
        var current = StringBuilder()

        for (unit in units) {
            // A single unit longer than the limit gets hard-split; without
            // this, one unbroken wall of text would produce a chunk far over
            // budget and blow the ContextBuilder token cap in one go.
            if (unit.length > MAX_CHUNK_CHARS) {
                if (current.isNotEmpty()) {
                    chunks += current.toString().trim()
                    current = StringBuilder()
                }
                unit.chunked(MAX_CHUNK_CHARS).forEach { chunks += it.trim() }
                continue
            }

            if (current.length + unit.length + 1 > MAX_CHUNK_CHARS) {
                chunks += current.toString().trim()
                current = StringBuilder(tailOverlap(current.toString()))
            }
            current.append(unit).append(' ')
        }

        if (current.isNotBlank()) chunks += current.toString().trim()
        return chunks.filter { it.length >= MIN_CHUNK_CHARS }
    }

    /** Last [OVERLAP_CHARS] characters, trimmed to a word boundary. */
    private fun tailOverlap(text: String): String {
        if (text.length <= OVERLAP_CHARS) return "$text "
        val tail = text.takeLast(OVERLAP_CHARS)
        val spaceIdx = tail.indexOf(' ')
        return if (spaceIdx >= 0) tail.substring(spaceIdx + 1) + " " else "$tail "
    }

    private companion object {
        const val TAG = "RagRetriever"
        const val MAX_CHUNK_CHARS = 900
        const val MIN_CHUNK_CHARS = 40
        const val OVERLAP_CHARS = 120

        val PARAGRAPH_BREAK = Regex("\n\\s*\n")
        val SENTENCE_BREAK = Regex("(?<=[.!?])\\s+")
    }
}
