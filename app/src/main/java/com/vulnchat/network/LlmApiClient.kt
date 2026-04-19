package com.vulnchat.network

import android.util.Log
import com.vulnchat.BuildConfig
import com.vulnchat.security.ApiKeyProvider
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.logging.HttpLoggingInterceptor
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * LlmApiClient — the single exit point for all outbound LLM requests.
 *
 * Responsibilities:
 *   1. Attach the API key from ApiKeyProvider (never hardcoded here).
 *   2. Enforce TLS 1.3 + certificate pinning on every connection.
 *   3. Stream token-by-token responses via SSE as a Flow<String>.
 *   4. Provide a blocking classifyIntent call used by InputFilter.
 *
 * Two build modes (BuildConfig.SECURE_MODE):
 *   VULNERABLE — no cert pinning, verbose logging, plain key in header.
 *   HARDENED   — pinning enforced, logging stripped, key via Keystore.
 *
 * Portfolio demo note:
 *   The pinning bypass demo uses MitmProxy + a custom CA. On the
 *   vulnerable build the proxy intercepts the request, and you can read
 *   the API key and full prompt in clear text. On the hardened build the
 *   handshake fails with a CertificatePinningException.
 */
class LlmApiClient(private val keyProvider: ApiKeyProvider) {

    // ─────────────────────────────────────────────────────────────────
    // OkHttp client construction
    // ─────────────────────────────────────────────────────────────────

    private val httpClient: OkHttpClient by lazy { buildClient() }

    private fun buildClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)   // SSE streams can be long
            .writeTimeout(15, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)     // fail fast — no silent retries

        if (BuildConfig.SECURE_MODE) {
            // ── Hardened: TLS 1.3 only, no cleartext ─────────────────
            builder
                .connectionSpecs(
                    listOf(
                        ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                            .build()
                    )
                )
                .certificatePinner(buildCertificatePinner())
                /*
                 * VULNERABLE demo: comment out certificatePinner() above,
                 * run MitmProxy with `mitmproxy --mode transparent`,
                 * and route the emulator's traffic through it.
                 * The hardened build's handshake will fail here — show the
                 * SSLPeerUnverifiedException in Logcat.
                 */
                .addInterceptor(SecurityHeaderInterceptor())
                .addInterceptor(RateLimitInterceptor())
        } else {
            // ── Vulnerable: verbose logging, no pinning ───────────────
            val logging = HttpLoggingInterceptor { msg -> Log.d("VulnChat[VULN]", msg) }
            logging.level = HttpLoggingInterceptor.Level.BODY
            builder.addInterceptor(logging)
            // Intentionally no cert pinning, no ConnectionSpec restriction.
            // A MitmProxy CA installed on the device intercepts everything.
        }

        return builder.build()
    }

    /**
     * Certificate pinner for api.anthropic.com.
     *
     * Pin values are the SHA-256 fingerprints of the leaf + intermediate
     * certificates. Always include at least one backup pin (the CA or
     * intermediate) so a leaf cert rotation doesn't brick the app.
     *
     * How to get the pins:
     *   okhttp-tls CertificatePinner.pin(cert)
     *   or: openssl s_client -connect api.anthropic.com:443 | \
     *         openssl x509 -pubkey -noout | \
     *         openssl pkey -pubin -outform DER | \
     *         openssl dgst -sha256 -binary | base64
     *
     * IMPORTANT: update these pins before the cert expires (check ~90
     * days before expiry). Stale pins = production outage.
     */
    private fun buildCertificatePinner(): CertificatePinner {
        return CertificatePinner.Builder()
            .add(
                API_HOST,
                // Leaf certificate pin (replace with real value)
                "sha256/REPLACE_WITH_REAL_LEAF_PIN=",
                // Intermediate CA pin — backup if leaf rotates
                "sha256/REPLACE_WITH_REAL_INTERMEDIATE_PIN="
            )
            .build()
    }

    // ─────────────────────────────────────────────────────────────────
    // Public API — streaming chat completion
    // ─────────────────────────────────────────────────────────────────

    /**
     * Sends a full conversation to the LLM and returns a Flow that
     * emits each text delta as it arrives via SSE.
     *
     * The caller (ChatViewModel) collects the flow and appends each
     * delta to the in-progress assistant message bubble.
     *
     * @param systemPrompt  The hardened or naive system prompt string.
     * @param messages      Full conversation history in role/content pairs.
     */
    fun streamChatCompletion(
        systemPrompt: String,
        messages: List<ChatMessage>
    ): Flow<StreamEvent> = callbackFlow {

        val body = buildChatRequestBody(systemPrompt, messages, stream = true)
        val request = buildRequest(CHAT_ENDPOINT, body)

        val call = httpClient.newCall(request)

        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                close(LlmNetworkException("Chat request failed", e))
            }

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (!response.isSuccessful) {
                        val errorBody = response.body?.string() ?: "empty body"
                        close(LlmApiException(response.code, errorBody))
                        return
                    }

                    try {
                        parseSseStream(response.body!!) { event ->
                            trySend(event)
                        }
                        close() // stream finished cleanly
                    } catch (e: Exception) {
                        close(e)
                    }
                }
            }
        })

        awaitClose { call.cancel() }
    }

    // ─────────────────────────────────────────────────────────────────
    // Public API — blocking classifier call (used by InputFilter)
    // ─────────────────────────────────────────────────────────────────

    /**
     * Sends the classifier prompt and returns the raw model response text.
     *
     * This is a suspending function wrapping an OkHttp callback — it
     * bridges the callback world into coroutines via
     * suspendCancellableCoroutine.
     *
     * Not streamed — the classifier response is short (one word) so SSE
     * overhead is unnecessary.
     */
    suspend fun classifyIntent(classifierPrompt: String): String =
        suspendCancellableCoroutine { cont ->

            val body = buildClassifierRequestBody(classifierPrompt)
            val request = buildRequest(CHAT_ENDPOINT, body)
            val call = httpClient.newCall(request)

            cont.invokeOnCancellation { call.cancel() }

            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    cont.resumeWithException(LlmNetworkException("Classifier call failed", e))
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        if (!response.isSuccessful) {
                            cont.resumeWithException(
                                LlmApiException(response.code, response.body?.string() ?: "")
                            )
                            return
                        }
                        try {
                            val json = JSONObject(response.body!!.string())
                            val text = json
                                .getJSONArray("content")
                                .getJSONObject(0)
                                .getString("text")
                            cont.resume(text)
                        } catch (e: Exception) {
                            cont.resumeWithException(
                                LlmParseException("Failed to parse classifier response", e)
                            )
                        }
                    }
                }
            })
        }

    // ─────────────────────────────────────────────────────────────────
    // Request builders
    // ─────────────────────────────────────────────────────────────────

    private fun buildRequest(endpoint: String, body: String): Request {
        val apiKey = keyProvider.getApiKey()

        return Request.Builder()
            .url("$BASE_URL$endpoint")
            .post(body.toRequestBody(JSON_MEDIA_TYPE))
            // Anthropic auth header
            .header("x-api-key", apiKey)
            .header("anthropic-version", ANTHROPIC_API_VERSION)
            .header("content-type", "application/json")
            // Accept SSE for streaming calls — server ignores for non-stream requests
            .header("accept", "text/event-stream")
            .build()
    }

    private fun buildChatRequestBody(
        systemPrompt: String,
        messages: List<ChatMessage>,
        stream: Boolean
    ): String {
        val messagesArray = JSONArray().apply {
            messages.forEach { msg ->
                put(JSONObject().apply {
                    put("role", msg.role.value)
                    put("content", msg.content)
                })
            }
        }

        return JSONObject().apply {
            put("model", MODEL_ID)
            put("max_tokens", MAX_TOKENS)
            put("system", systemPrompt)
            put("messages", messagesArray)
            put("stream", stream)
        }.toString()
    }

    private fun buildClassifierRequestBody(prompt: String): String {
        return JSONObject().apply {
            put("model", CLASSIFIER_MODEL_ID)  // faster/cheaper model for binary classify
            put("max_tokens", 10)              // "SAFE" or "ATTACK" only — hard cap
            put("messages", JSONArray().apply {
                put(JSONObject().apply {
                    put("role", "user")
                    put("content", prompt)
                })
            })
            put("stream", false)
        }.toString()
    }

    // ─────────────────────────────────────────────────────────────────
    // SSE parser
    // ─────────────────────────────────────────────────────────────────

    /**
     * Reads an SSE response body line by line and invokes onEvent for
     * each text delta and for the final StreamEvent.Done signal.
     *
     * Anthropic SSE format:
     *   event: content_block_delta
     *   data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}
     *
     *   event: message_stop
     *   data: {"type":"message_stop"}
     *
     * We only care about content_block_delta events — everything else is
     * metadata (token usage, stop reason) that we log but don't surface.
     */
    private fun parseSseStream(body: ResponseBody, onEvent: (StreamEvent) -> Unit) {
        body.source().use { source ->
            val reader = source.inputStream().bufferedReader()
            var eventType = ""

            reader.forEachLine { line ->
                when {
                    line.startsWith("event:") -> {
                        eventType = line.removePrefix("event:").trim()
                    }
                    line.startsWith("data:") -> {
                        val data = line.removePrefix("data:").trim()
                        if (data == "[DONE]") {
                            onEvent(StreamEvent.Done)
                            return@forEachLine
                        }
                        handleSseData(eventType, data, onEvent)
                    }
                    // Empty line = SSE event separator — reset event type
                    line.isBlank() -> {
                        eventType = ""
                    }
                }
            }
            onEvent(StreamEvent.Done)
        }
    }

    private fun handleSseData(
        eventType: String,
        data: String,
        onEvent: (StreamEvent) -> Unit
    ) {
        if (eventType != "content_block_delta") return

        try {
            val json = JSONObject(data)
            val delta = json.optJSONObject("delta") ?: return
            if (delta.optString("type") != "text_delta") return
            val text = delta.optString("text")
            if (text.isNotEmpty()) {
                onEvent(StreamEvent.TextDelta(text))
            }
        } catch (e: Exception) {
            // Malformed SSE data — log and skip rather than crash the stream.
            if (BuildConfig.DEBUG) Log.w(TAG, "Failed to parse SSE data: $data", e)
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────

    private companion object {
        const val TAG = "LlmApiClient"
        const val BASE_URL = "https://api.anthropic.com"
        const val API_HOST = "api.anthropic.com"
        const val CHAT_ENDPOINT = "/v1/messages"
        const val ANTHROPIC_API_VERSION = "2023-06-01"

        // Main model for conversation
        const val MODEL_ID = "claude-haiku-4-5-20251001"
        // Lighter model for the InputFilter classifier — lower latency, lower cost
        const val CLASSIFIER_MODEL_ID = "claude-haiku-4-5-20251001"

        const val MAX_TOKENS = 1024
        val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Supporting types
// ─────────────────────────────────────────────────────────────────────

/** A single message in the conversation history. */
data class ChatMessage(
    val role: Role,
    val content: String
) {
    enum class Role(val value: String) {
        USER("user"),
        ASSISTANT("assistant")
    }
}

/** Events emitted by the SSE streaming flow. */
sealed class StreamEvent {
    /** A text fragment to append to the current assistant message. */
    data class TextDelta(val text: String) : StreamEvent()
    /** The stream has ended cleanly. */
    object Done : StreamEvent()
    /** An error occurred mid-stream. */
    data class Error(val cause: Throwable) : StreamEvent()
}

/** Exception types — typed so the ViewModel can handle each distinctly. */
class LlmNetworkException(msg: String, cause: Throwable? = null) : IOException(msg, cause)
class LlmApiException(val code: Int, val body: String) : Exception("API error $code: $body")
class LlmParseException(msg: String, cause: Throwable? = null) : Exception(msg, cause)
