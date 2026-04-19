package com.vulnchat.network

import android.os.SystemClock
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * BackendProxyClient — the preferred production architecture for API key safety.
 *
 * Rather than storing the LLM API key on-device (even Keystore-backed),
 * this client routes all requests through a thin backend proxy:
 *
 *   Android app  ──JWT──▶  Proxy server  ──API key──▶  Anthropic API
 *
 * The device never sees the real API key at any point. Even a rooted
 * device with Frida attached cannot extract what was never there.
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  Why this is the right answer in an interview                   │
 * │                                                                 │
 * │  "On-device key protection is a trade-off, not a solution.      │
 * │   Keystore makes extraction harder, but a motivated attacker    │
 * │   on a rooted device can still hook the decryption call.        │
 * │   The correct answer is a backend proxy — the key never touches │
 * │   the device at all."                                           │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * JWT lifecycle:
 *   1. authenticate exchanges a device attestation token for a short-
 *      lived JWT (15 minutes by default).
 *   2. All subsequent chat requests attach the JWT via Bearer header.
 *   3. On 401, the client re-authenticates transparently.
 *   4. The proxy server validates the JWT and injects the real API key.
 *
 * Demo proxy server:
 *   See /server/proxy.py — a minimal FastAPI service you can run locally
 *   or deploy to Cloud Run for the demo.
 */
class BackendProxyClient(private val proxyBaseUrl: String) {

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .build()

    // ── JWT state ─────────────────────────────────────────────────────

    @Volatile private var jwtToken: String? = null
    @Volatile private var jwtExpiryMs: Long = 0L

    private val isTokenValid: Boolean
        get() = jwtToken != null &&
                SystemClock.elapsedRealtime() < (jwtExpiryMs - TOKEN_EXPIRY_BUFFER_MS)

    // ─────────────────────────────────────────────────────────────────
    // Authentication
    // ─────────────────────────────────────────────────────────────────

    /**
     * Exchanges a device attestation payload for a short-lived JWT.
     *
     * deviceAttestation should be a Play Integrity token in production.
     * For demo purposes it can be a static device ID from
     * Settings.Secure.ANDROID_ID — sufficient to demonstrate the flow.
     *
     * The proxy server validates the attestation and decides whether to
     * issue a JWT. This is the choke point for device-level abuse control.
     */
    suspend fun authenticate(deviceAttestation: String) {
        if (isTokenValid) return  // already have a valid token

        val body = JSONObject()
            .apply { put("attestation", deviceAttestation) }
            .toString()
            .toRequestBody(JSON_MEDIA_TYPE)

        val request = Request.Builder()
            .url("$proxyBaseUrl/auth/token")
            .post(body)
            .header("Content-Type", "application/json")
            .build()

        val response = httpClient.newCall(request).awaitResponse()

        response.use {
            if (!response.isSuccessful) {
                throw ProxyAuthException(
                    "Authentication failed: HTTP ${response.code} — ${response.body?.string()}"
                )
            }

            val json = JSONObject(response.body!!.string())
            jwtToken    = json.getString("token")
            val ttlSecs = json.getLong("expires_in")
            jwtExpiryMs = SystemClock.elapsedRealtime() + (ttlSecs * 1000)
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Streaming chat via proxy
    // ─────────────────────────────────────────────────────────────────

    /**
     * Forwards a chat request to the proxy server.
     *
     * The proxy:
     *   1. Validates the JWT.
     *   2. Injects the real Anthropic API key.
     *   3. Forwards the request and pipes the SSE stream back.
     *
     * On a 401 (token expired mid-session), the flow closes with
     * ProxyAuthException — the ViewModel triggers re-authentication.
     */
    fun streamViaProxy(
        systemPrompt: String,
        messages: List<ChatMessage>
    ): Flow<StreamEvent> = callbackFlow {

        val token = jwtToken.takeIf { isTokenValid }
            ?: run {
                close(ProxyAuthException("JWT not available — call authenticate() first"))
                return@callbackFlow
            }

        val requestBody = JSONObject().apply {
            put("system", systemPrompt)
            put("messages", JSONArray().apply {
                messages.forEach { msg ->
                    put(JSONObject().apply {
                        put("role", msg.role.value)
                        put("content", msg.content)
                    })
                }
            })
        }.toString().toRequestBody(JSON_MEDIA_TYPE)

        val request = Request.Builder()
            .url("$proxyBaseUrl/v1/chat")
            .post(requestBody)
            .header("Authorization", "Bearer $token")
            .header("Accept", "text/event-stream")
            .build()

        val call = httpClient.newCall(request)

        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                close(LlmNetworkException("Proxy request failed", e))
            }

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    when (response.code) {
                        401 -> {
                            jwtToken = null  // invalidate cached token
                            jwtExpiryMs = 0
                            close(ProxyAuthException("JWT rejected by proxy — re-authenticate"))
                            return
                        }
                        in 400..599 -> {
                            close(LlmApiException(response.code, response.body?.string() ?: ""))
                            return
                        }
                    }

                    try {
                        response.body!!.source().inputStream().bufferedReader()
                            .forEachLine { line ->
                                when {
                                    line.startsWith("data:") -> {
                                        val data = line.removePrefix("data:").trim()
                                        if (data == "[DONE]") {
                                            trySend(StreamEvent.Done)
                                            return@forEachLine  // end stream
                                        }
                                        parseProxySseLine(data)?.let { trySend(it) }
                                    }
                                }
                            }
                        close()
                    } catch (e: Exception) {
                        close(e)
                    }
                }
            }
        })

        awaitClose { call.cancel() }
    }

    // ─────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────

    private fun parseProxySseLine(data: String): StreamEvent.TextDelta? {
        return try {
            val json = JSONObject(data)
            val delta = json.optJSONObject("delta") ?: return null
            val text = delta.optString("text").takeIf { it.isNotEmpty() } ?: return null
            StreamEvent.TextDelta(text)
        } catch (e: Exception) {
            null  // malformed data — skip silently
        }
    }

    /**
     * Wraps an OkHttp Call in a suspend function.
     * Reusable coroutines bridge — avoids duplicating the
     * suspendCancellableCoroutine boilerplate throughout the client.
     */
    private suspend fun okhttp3.Call.awaitResponse(): Response =
        suspendCancellableCoroutine { cont ->
//            invokeOnCancellation { cancel() }
            enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    cont.resumeWithException(e)
                }
                override fun onResponse(call: Call, response: Response) {
                    cont.resume(response)
                }
            })
        }

    // ─────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────

    companion object {
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        /** Refresh the token this many milliseconds before it actually expires. */
        private const val TOKEN_EXPIRY_BUFFER_MS = 60_000L  // 1 minute buffer
    }
}

// ─────────────────────────────────────────────────────────────────────
// Exception types
// ─────────────────────────────────────────────────────────────────────

/** JWT exchange or validation failure. */
class ProxyAuthException(message: String) : Exception(message)
