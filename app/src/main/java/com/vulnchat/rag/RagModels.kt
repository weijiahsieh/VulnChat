package com.vulnchat.rag

/**
 * Core data models for the RAG pipeline.
 *
 * The central security concept here is [TrustLevel] — every document and
 * every chunk derived from it carries a provenance label that follows it
 * all the way into the LLM context. This is what makes the difference
 * between "we retrieved some text" and "we retrieved text from an
 * untrusted source and told the model to treat it as data".
 *
 * Portfolio interview point:
 *   Most RAG implementations treat all retrieved chunks identically.
 *   That works until someone plants a document. Provenance tracking is
 *   the cheapest control that meaningfully changes the blast radius of a
 *   poisoned document — the model is told which text it can trust and
 *   which it cannot, and the ContextBuilder frames each accordingly.
 */

/**
 * Trust level assigned at ingestion and carried through to the prompt.
 *
 * Assignment rules (enforced in DocumentSanitizer):
 *   TRUSTED   — shipped with the app, signed, or admin-provisioned.
 *               Never user-supplied at runtime.
 *   USER      — the user uploaded it themselves. They chose it, so it is
 *               more trustworthy than arbitrary web content, but still not
 *               authored by us.
 *   UNTRUSTED — fetched from a URL, shared into the app, or received from
 *               any third party. Assume it is adversarial.
 *
 * Default is UNTRUSTED. A document must earn a higher level; it never
 * gets one by omission.
 */
enum class TrustLevel {
    TRUSTED,
    USER,
    UNTRUSTED;

    /** Higher ordinal = less trusted. Used to pick the strictest framing. */
    fun isAtLeastAsTrustedAs(other: TrustLevel): Boolean = this.ordinal <= other.ordinal
}

/**
 * A document as ingested, before chunking.
 *
 * [sanitizationReport] is populated by DocumentSanitizer and retained so
 * the UI can show the user why a document was rejected or flagged.
 */
data class RagDocument(
    val id: String,
    val title: String,
    val content: String,
    val source: String,
    val trustLevel: TrustLevel = TrustLevel.UNTRUSTED,
    val ingestedAt: Long = System.currentTimeMillis(),
    val sanitizationReport: SanitizationReport? = null
) {
    val isIndexable: Boolean
        get() = sanitizationReport?.verdict == SanitizationVerdict.ACCEPTED ||
                sanitizationReport?.verdict == SanitizationVerdict.ACCEPTED_WITH_STRIPPING
}

/**
 * A chunk of a document, with its embedding vector and inherited provenance.
 *
 * [trustLevel] and [sourceTitle] are inherited from the parent document and
 * are NOT recomputed — a chunk can never be more trusted than its source.
 */
data class RagChunk(
    val id: String,
    val documentId: String,
    val sourceTitle: String,
    val trustLevel: TrustLevel,
    val text: String,
    val ordinal: Int,
    val embedding: FloatArray? = null
) {
    // FloatArray needs explicit equals/hashCode — the generated ones use
    // reference equality for arrays, which breaks set/map membership.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RagChunk) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

/**
 * A chunk paired with its retrieval score, returned by VectorIndex.
 */
data class ScoredChunk(
    val chunk: RagChunk,
    val score: Float
)

// ─────────────────────────────────────────────────────────────────────
// Sanitization results
// ─────────────────────────────────────────────────────────────────────

enum class SanitizationVerdict {
    /** Clean — index as-is. */
    ACCEPTED,

    /** Injection markers found and neutralised — index the stripped version. */
    ACCEPTED_WITH_STRIPPING,

    /** Too many or too severe findings — do not index. */
    REJECTED
}

/**
 * The result of running DocumentSanitizer over a document.
 *
 * [cleanedContent] is what actually gets chunked and indexed — it may
 * differ from the original if instruction stripping was applied.
 */
data class SanitizationReport(
    val verdict: SanitizationVerdict,
    val findings: List<Finding>,
    val cleanedContent: String,
    val originalLength: Int,
    val cleanedLength: Int
) {
    data class Finding(
        val rule: String,
        val category: Category,
        val severity: Severity,
        /** Character offset in the original content where the match started. */
        val offset: Int,
        /** Short redacted excerpt, safe for logging and UI display. */
        val excerpt: String
    )

    enum class Category {
        INSTRUCTION_OVERRIDE,   // "ignore previous instructions"
        ROLE_HIJACK,            // "you are now DAN"
        PROMPT_EXTRACTION,      // "reveal your system prompt"
        EXFILTRATION,           // "send this to https://..."
        HIDDEN_CONTENT,         // zero-width chars, white-on-white markers
        DELIMITER_SPOOFING      // fake <document> / </user_message> tags
    }

    enum class Severity {
        /** Neutralise and continue. */
        LOW,

        /** Neutralise, but count toward the rejection threshold. */
        MEDIUM,

        /** Reject the whole document immediately. */
        HIGH
    }

    val wasModified: Boolean get() = originalLength != cleanedLength
}
