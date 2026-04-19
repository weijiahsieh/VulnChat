package com.vulnchat.data

import com.vulnchat.network.ChatMessage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * ConversationRepository — single source of truth for the conversation history.
 *
 * Responsibilities:
 *   • Maintains the ordered list of [UiMessage] objects rendered by ChatScreen.
 *   • Maintains a parallel list of [ChatMessage] objects sent to the LLM API
 *     (role/content pairs only — no UI state).
 *   • Enforces a rolling context window so the API payload never exceeds
 *     the model's context limit.
 *   • Exposes both lists as [StateFlow] so ChatViewModel and ChatScreen
 *     can observe them without coupling to each other.
 *
 * In-memory only — conversation history is intentionally not persisted to
 * disk. This is a deliberate security decision: no SQLite database means
 * no conversation data recoverable via `adb backup` or root file access.
 * For a production app that needs persistence, use Room with SQLCipher.
 *
 * Portfolio note:
 *   "Why no persistence?" is a likely interview question. The answer
 *   demonstrates threat modelling: the attack surface of an on-device
 *   database (adb backup, root extraction, unencrypted WAL files) outweighs
 *   the UX benefit of conversation history for this demo scope.
 */
class ConversationRepository {

    // ─────────────────────────────────────────────────────────────────
    // UI state — what ChatScreen observes
    // ─────────────────────────────────────────────────────────────────

    private val _uiMessages = MutableStateFlow<List<UiMessage>>(emptyList())
    val uiMessages: StateFlow<List<UiMessage>> = _uiMessages.asStateFlow()

    // ─────────────────────────────────────────────────────────────────
    // API state — what LlmApiClient receives
    // ─────────────────────────────────────────────────────────────────

    private val _apiMessages = MutableStateFlow<List<ChatMessage>>(emptyList())
    val apiMessages: StateFlow<List<ChatMessage>> = _apiMessages.asStateFlow()

    // ─────────────────────────────────────────────────────────────────
    // Mutation — called by ChatViewModel only
    // ─────────────────────────────────────────────────────────────────

    /** Appends a user message to both lists. */
    fun addUserMessage(text: String, displayText: String = text) {
        val id = nextId()
        _uiMessages.update { it + UiMessage(
            id      = id,
            role    = UiMessage.Role.USER,
            content = displayText,
            state   = UiMessage.State.DONE
        )}
        _apiMessages.update { trimmed(it + ChatMessage(ChatMessage.Role.USER, text)) }
    }

    /**
     * Appends a placeholder assistant message and returns its ID.
     * The placeholder is updated in-place as SSE deltas arrive.
     */
    fun beginAssistantMessage(): String {
        val id = nextId()
        _uiMessages.update { it + UiMessage(
            id      = id,
            role    = UiMessage.Role.ASSISTANT,
            content = "",
            state   = UiMessage.State.STREAMING
        )}
        return id
    }

    /** Appends a text delta to the in-progress assistant message. */
    fun appendAssistantDelta(id: String, delta: String) {
        _uiMessages.update { messages ->
            messages.map { msg ->
                if (msg.id == id) msg.copy(content = msg.content + delta)
                else msg
            }
        }
    }

    /**
     * Finalises the assistant message — transitions it from STREAMING
     * to DONE and adds the completed content to the API history.
     */
    fun finaliseAssistantMessage(id: String) {
        val completed = _uiMessages.value.find { it.id == id } ?: return
        _uiMessages.update { messages ->
            messages.map { msg ->
                if (msg.id == id) msg.copy(state = UiMessage.State.DONE) else msg
            }
        }
        if (completed.content.isNotBlank()) {
            _apiMessages.update { trimmed(it + ChatMessage(
                role    = ChatMessage.Role.ASSISTANT,
                content = completed.content
            ))}
        }
    }

    /**
     * Marks an in-progress assistant message as errored and removes it
     * from the API history (an errored turn should not confuse the model).
     */
    fun errorAssistantMessage(id: String, errorText: String) {
        _uiMessages.update { messages ->
            messages.map { msg ->
                if (msg.id == id) msg.copy(
                    content = errorText,
                    state   = UiMessage.State.ERROR
                ) else msg
            }
        }
        // Do not add errored messages to API history
    }

    /**
     * Appends a system-generated notice (blocked message, rate limit warning).
     * These are UI-only — they never enter the API history.
     */
    fun addSystemNotice(text: String) {
        _uiMessages.update { it + UiMessage(
            id      = nextId(),
            role    = UiMessage.Role.SYSTEM,
            content = text,
            state   = UiMessage.State.DONE
        )}
    }

    /** Clears all messages from both lists. */
    fun clear() {
        _uiMessages.update { emptyList() }
        _apiMessages.update { emptyList() }
    }

    // ─────────────────────────────────────────────────────────────────
    // Context window management
    // ─────────────────────────────────────────────────────────────────

    /**
     * Trims the API message list to stay within the rolling context window.
     *
     * Strategy: drop oldest messages in pairs (user + assistant) to
     * maintain role alternation invariant required by the Anthropic API.
     * Always keep the most recent [MIN_MESSAGES_TO_KEEP] messages.
     *
     * A rough token estimate is used (4 chars ≈ 1 token) — precise enough
     * for windowing without pulling in a full tokeniser library.
     */
    private fun trimmed(messages: List<ChatMessage>): List<ChatMessage> {
        var result = messages
        while (estimatedTokens(result) > MAX_CONTEXT_TOKENS &&
               result.size > MIN_MESSAGES_TO_KEEP) {
            // Drop the oldest pair (must keep role alternation)
            result = if (result.size >= 2) result.drop(2) else result.drop(1)
        }
        return result
    }

    private fun estimatedTokens(messages: List<ChatMessage>): Int =
        messages.sumOf { it.content.length / CHARS_PER_TOKEN }

    // ─────────────────────────────────────────────────────────────────
    // ID generation
    // ─────────────────────────────────────────────────────────────────

    private var idCounter = 0
    private fun nextId(): String = "msg_${++idCounter}"

    // ─────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────

    companion object {
        private const val MAX_CONTEXT_TOKENS   = 6_000
        private const val MIN_MESSAGES_TO_KEEP = 4     // always keep last 2 turns
        private const val CHARS_PER_TOKEN      = 4
    }
}

// ─────────────────────────────────────────────────────────────────────
// UiMessage — the UI data model, separate from the API data model
// ─────────────────────────────────────────────────────────────────────

/**
 * Represents a single message bubble in the chat UI.
 *
 * Deliberately separate from [ChatMessage] — the API model has no concept
 * of streaming state, error state, or system notices. Keeping them separate
 * avoids leaking UI concerns into the network layer.
 */
data class UiMessage(
    val id:      String,
    val role:    Role,
    val content: String,
    val state:   State
) {
    enum class Role    { USER, ASSISTANT, SYSTEM }
    enum class State   { STREAMING, DONE, ERROR }
}
