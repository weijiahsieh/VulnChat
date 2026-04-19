package com.vulnchat

import android.app.Application
import com.vulnchat.security.ApiKeyProvider

/**
 * Application entry point.
 *
 * Calls ApiKeyProvider.provisionIfNeeded at startup so the Keystore
 * key is generated before the first chat message is sent, avoiding
 * first-message latency in the hardened build.
 *
 * In the vulnerable build provisionIfNeeded is a no-op.
 */
class VulnChatApplication : Application() {

    // Exposed so ViewModels can access it via (application as VulnChatApplication)
    lateinit var apiKeyProvider: ApiKeyProvider
        private set

    override fun onCreate() {
        super.onCreate()
        apiKeyProvider = ApiKeyProvider(applicationContext)
        apiKeyProvider.provisionIfNeeded()
    }
}
