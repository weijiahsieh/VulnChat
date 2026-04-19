package com.vulnchat.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.vulnchat.BuildConfig
import com.vulnchat.VulnChatApplication
import com.vulnchat.data.ConversationRepository
import com.vulnchat.data.UiMessage
import com.vulnchat.network.LlmApiClient
import com.vulnchat.network.LlmNetworkException
import com.vulnchat.network.LlmApiException
import com.vulnchat.network.RateLimitException
import com.vulnchat.network.StreamEvent
import com.vulnchat.security.InputFilter
import com.vulnchat.security.OutputModerator
import com.vulnchat.security.SystemPrompt
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * ChatViewModel — the central coordinator for the VulnChat conversation flow.
 *
 * This is where all four security layers are wired together:
 *
 *   User sends message
 *       │
 *       ▼
 *   [InputFilter]          Stage 1: regex  →  Stage 2: LLM classifier
 *       │ Clean
 *       ▼
 *   [SystemPrompt]         Wraps user message in structural delimiter
 *       │
 *       ▼
 *   [LlmApiClient]         TLS 1.3 + cert pinning + rate limiter + SSE stream
 *       │ StreamEvent.TextDelta
 *       ▼
 *   [OutputModerator]      Scans each chunk for secrets / leakage / PII
 *       │ Clean
 *       ▼
 *   [ConversationRepository]  Appends delta → ChatScreen observes StateFlow
 *
 * SECURE_MODE flag:
 *   false → InputFilter is bypassed, OutputModerator is bypassed, naive
 *           SystemPrompt used. Raw attack surface exposed for demo.
 *   true  → All gates active. Each layer independently sufficient to block
 *           the demonstrated attacks (defence in depth).
 *
 * Debug-only bypass:
 *   Set [skipInputFilter] = true to demonstrate OutputModerator in isolation
 *   — lets an injected message past Stage 1/2 so the output scanner fires.
 *   Only available in debug + vulnerable builds, never in release.
 */
class ChatViewModel(application: Application) : AndroidViewModel(application) {

    // ── Debug bypass flag — see class KDoc ──────────────────────────────────
    var skipInputFilter: Boolean = false
        set(value) {
            // Safety guard: bypass only available in debug + vulnerable builds
            field = value && BuildConfig.DEBUG && !BuildConfig.SECURE_MODE
        }

    // ─────────────────────────────────────────────────────────────────
    // Dependencies
    // ─────────────────────────────────────────────────────────────────

    private val app get() = getApplication<VulnChatApplication>()

    private val repository    = ConversationRepository()
    private val apiClient     = LlmApiClient(app.apiKeyProvider)
    private val inputFilter   = InputFilter(apiClient)
    private val outputMod     = OutputModerator()

    // ─────────────────────────────────────────────────────────────────
    // UI state exposed to ChatScreen
    // ─────────────────────────────────────────────────────────────────

    val messages: StateFlow<List<UiMessage>> = repository.uiMessages

    private val _uiState = MutableStateFlow(ChatUiState())
    val uiState: StateFlow<ChatUiState> = _uiState.asStateFlow()

    // Tracks the active streaming job so the user can cancel mid-response
    private var streamingJob: Job? = null

    // ─────────────────────────────────────────────────────────────────
    // User actions
    // ─────────────────────────────────────────────────────────────────

    /**
     * Primary entry point — called by ChatScreen when the user sends a message.
     *
     * Suspends internally via coroutines; the caller just invokes [sendMessage]
     * and observes [messages] and [uiState] for updates.
     */
    fun sendMessage(rawInput: String) {
        val trimmed = rawInput.trim()
        if (trimmed.isBlank() || _uiState.value.isStreaming) return

        streamingJob = viewModelScope.launch {
            _uiState.update { it.copy(isStreaming = true, inputError = null) }

            // ── Gate 1: Input filter ─────────────────────────────────────────
            val filterResult = if (skipInputFilter) {
                InputFilter.FilterResult.Clean(trimmed)
            } else {
                inputFilter.evaluate(trimmed)
            }

            when (filterResult) {
                is InputFilter.FilterResult.BlockedByRegex -> {
                    handleInputBlocked(
                        userInput = trimmed,
                        reason    = "Message blocked (security policy).",
                        logTag    = "regex:${filterResult.matchedRule}"
                    )
                    return@launch
                }
                is InputFilter.FilterResult.BlockedByClassifier -> {
                    handleInputBlocked(
                        userInput = trimmed,
                        reason    = "Message blocked (security policy).",
                        logTag    = "classifier"
                    )
                    return@launch
                }
                is InputFilter.FilterResult.ClassifierError -> {
                    handleInputBlocked(
                        userInput = trimmed,
                        reason    = "Security check failed. Please try again.",
                        logTag    = "classifier_error"
                    )
                    return@launch
                }
                is InputFilter.FilterResult.Clean -> {
                    // Continue with sanitised input
                }
            }

            val sanitisedInput = filterResult.sanitised

            // ── Add user message to UI and API history ───────────────────────
            repository.addUserMessage(
                text        = SystemPrompt.wrapUserMessage(sanitisedInput),
                displayText = sanitisedInput   // show unwrapped text in the bubble
            )

            // ── Begin assistant response placeholder ─────────────────────────
            val assistantMsgId = repository.beginAssistantMessage()
            outputMod.reset()

            // ── Gate 2–4: Stream through LLM + OutputModerator ───────────────
            runStreamingResponse(assistantMsgId)
        }
    }

    /** Cancels an in-progress streaming response. */
    fun cancelStreaming() {
        streamingJob?.cancel()
        streamingJob = null
        _uiState.update { it.copy(isStreaming = false) }
    }

    /** Clears all conversation history. */
    fun clearConversation() {
        cancelStreaming()
        repository.clear()
        outputMod.reset()
    }

    // ─────────────────────────────────────────────────────────────────
    // Streaming response handler
    // ─────────────────────────────────────────────────────────────────

    private suspend fun runStreamingResponse(assistantMsgId: String) {
        try {
            apiClient
                .streamChatCompletion(
                    systemPrompt = SystemPrompt.get(),
                    messages     = repository.apiMessages.value
                )
                .catch { e -> emit(StreamEvent.Error(e)) }
                .collect { event ->
                    when (event) {
                        is StreamEvent.TextDelta -> handleDelta(assistantMsgId, event.text)
                        is StreamEvent.Done      -> handleStreamDone(assistantMsgId)
                        is StreamEvent.Error     -> handleStreamError(assistantMsgId, event.cause)
                    }
                }
        } catch (e: CancellationException) {
            // User cancelled — leave partial response as-is
            repository.finaliseAssistantMessage(assistantMsgId)
            _uiState.update { it.copy(isStreaming = false) }
        } catch (e: RateLimitException) {
            repository.errorAssistantMessage(assistantMsgId, e.message ?: "Rate limit exceeded.")
            _uiState.update { it.copy(isStreaming = false, inputError = e.message) }
        } catch (e: LlmNetworkException) {
            repository.errorAssistantMessage(assistantMsgId, "Network error. Check your connection.")
            _uiState.update { it.copy(isStreaming = false) }
        } catch (e: LlmApiException) {
            repository.errorAssistantMessage(assistantMsgId, "API error (${e.code}). Please retry.")
            _uiState.update { it.copy(isStreaming = false) }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Per-event handlers
    // ─────────────────────────────────────────────────────────────────

    /**
     * Passes each SSE delta through OutputModerator before appending.
     * On violation: stops the stream, discards the partial response,
     * and shows a blocked-message notice.
     */
    private fun handleDelta(assistantMsgId: String, delta: String) {
        when (val result = outputMod.scanChunk(delta)) {
            is OutputModerator.ScanResult.Clean -> {
                repository.appendAssistantDelta(assistantMsgId, result.text)
            }
            is OutputModerator.ScanResult.Blocked -> {
                // Discard whatever was partially rendered and replace with notice
                repository.errorAssistantMessage(
                    id        = assistantMsgId,
                    errorText = blockedOutputMessage(result.violation)
                )
                _uiState.update { it.copy(isStreaming = false) }
                cancelStreaming()
            }
        }
    }

    private fun handleStreamDone(assistantMsgId: String) {
        repository.finaliseAssistantMessage(assistantMsgId)
        _uiState.update { it.copy(isStreaming = false) }
    }

    private fun handleStreamError(assistantMsgId: String, cause: Throwable) {
        val msg = when (cause) {
            is RateLimitException   -> cause.message ?: "Rate limit exceeded."
            is LlmNetworkException  -> "Network error. Check your connection."
            is LlmApiException      -> "API error (${cause.code}). Please retry."
            else                    -> "Something went wrong. Please retry."
        }
        repository.errorAssistantMessage(assistantMsgId, msg)
        _uiState.update { it.copy(isStreaming = false) }
    }

    // ─────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────

    /**
     * Shows the user message in the UI (so they can see what they sent)
     * but adds a system notice below it explaining the block.
     * The user message is NOT added to the API history.
     */
    private fun handleInputBlocked(userInput: String, reason: String, logTag: String) {
        repository.addUserMessage(text = userInput, displayText = userInput)
        repository.addSystemNotice("⚠ $reason")
        _uiState.update { it.copy(isStreaming = false, inputError = reason) }

        if (BuildConfig.DEBUG) {
            android.util.Log.w("ChatViewModel", "Input blocked [$logTag]: ${userInput.take(60)}")
        }
    }

    /**
     * Maps an [OutputModerator.Violation] to a user-visible message.
     * Deliberately vague — does not tell the user which rule fired.
     */
    private fun blockedOutputMessage(violation: OutputModerator.Violation): String {
        return when (violation.category) {
            OutputModerator.Category.SECRET_LEAKAGE   ->
                "⚠ Response blocked: contained credential data."
            OutputModerator.Category.PROMPT_LEAKAGE   ->
                "⚠ Response blocked: contained system configuration data."
            OutputModerator.Category.PII               ->
                "⚠ Response blocked: contained personal information."
            OutputModerator.Category.EXFILTRATION      ->
                "⚠ Response blocked: contained suspicious data patterns."
            OutputModerator.Category.POLICY_VIOLATION  ->
                "⚠ Response blocked: violated output policy."
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// UI state
// ─────────────────────────────────────────────────────────────────────

data class ChatUiState(
    val isStreaming: Boolean = false,
    val inputError: String? = null
)
