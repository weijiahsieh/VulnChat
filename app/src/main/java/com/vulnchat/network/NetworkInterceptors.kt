package com.vulnchat.network

import android.os.SystemClock
import android.util.Log
import okhttp3.Interceptor
import okhttp3.Response
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * SecurityHeaderInterceptor — adds defensive headers to every outbound request.
 *
 * 1. Strips the User-Agent to a minimal non-identifying string.
 *    The default OkHttp UA leaks the library version and Android API level —
 *    useful to a fingerprinting attacker.
 *
 * 2. Removes headers that can carry unintended identity data
 *    (Cookie, Referer) — relevant if a compromised WebView runs in the
 *    same process as the chat UI.
 *
 * 3. Adds X-Content-Type-Options to resist MIME-sniffing on the response.
 *
 * Portfolio demo note:
 *   Attach MitmProxy on the vulnerable build and show the full OkHttp UA
 *   and any leaked headers. On the hardened build they're gone.
 */
class SecurityHeaderInterceptor : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val sanitised = chain.request().newBuilder()
            .header("User-Agent", "VulnChat-Android/1.0")
            .removeHeader("Cookie")
            .removeHeader("Referer")
            .removeHeader("X-Forwarded-For")
            .header("X-Content-Type-Options", "nosniff")
            .build()

        return chain.proceed(sanitised)
    }
}

/**
 * RateLimitInterceptor — client-side token-bucket throttle.
 *
 * Defends against two threat scenarios:
 *
 *   1. A prompt injection causes the ViewModel to enter an unintended
 *      tight loop — burning API quota rapidly before the user notices.
 *
 *   2. An attacker extracts the APK, patches the UI, and scripted-hammers
 *      the endpoint using the embedded API key (vulnerable build).
 *
 * Design: rolling time window. When the window expires, both counters
 * reset. Separate counters for chat vs classifier calls so InputFilter's
 * classifier requests don't cannibalize the user-visible chat quota.
 *
 * On limit hit: throws [RateLimitException] immediately — no queuing.
 * The ViewModel catches this and shows a user-visible cooldown message.
 */
class RateLimitInterceptor : Interceptor {

    private val windowStart = AtomicLong(SystemClock.elapsedRealtime())
    private val chatCount = AtomicInteger(0)
    private val classifierCount = AtomicInteger(0)

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val isClassifier = request.header(CLASSIFIER_MARKER_HEADER) != null

        // Reset window if expired
        val now = SystemClock.elapsedRealtime()
        val windowAge = now - windowStart.get()
        if (windowAge > WINDOW_MS) {
            windowStart.set(now)
            chatCount.set(0)
            classifierCount.set(0)
        }

        val counter = if (isClassifier) classifierCount else chatCount
        val limit   = if (isClassifier) MAX_CLASSIFIER_PER_WINDOW else MAX_CHAT_PER_WINDOW

        val count = counter.incrementAndGet()
        if (count > limit) {
            counter.decrementAndGet()
            val cooldownSec = (WINDOW_MS - windowAge) / 1000
            Log.w(TAG, "Rate limit: ${if (isClassifier) "classifier" else "chat"} " +
                    "$count/$limit, resets in ${cooldownSec}s")
            throw RateLimitException(
                "Too many messages. Please wait ${cooldownSec}s before sending again."
            )
        }

        // Strip the internal marker before the request leaves the device —
        // the Anthropic API would reject an unknown header.
        val cleaned = request.newBuilder()
            .removeHeader(CLASSIFIER_MARKER_HEADER)
            .build()

        return chain.proceed(cleaned)
    }

    companion object {
        private const val TAG = "RateLimitInterceptor"

        /** Added by LlmApiClient to flag classifier calls; stripped here. */
        const val CLASSIFIER_MARKER_HEADER = "X-Internal-Classifier"

        const val WINDOW_MS: Long                = 60_000L
        const val MAX_CHAT_PER_WINDOW: Int       = 10
        const val MAX_CLASSIFIER_PER_WINDOW: Int = 20
    }
}

/** Thrown by [RateLimitInterceptor] when the per-window limit is exceeded. */
class RateLimitException(message: String) : Exception(message)
