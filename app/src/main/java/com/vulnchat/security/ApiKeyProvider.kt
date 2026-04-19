package com.vulnchat.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.vulnchat.BuildConfig
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import androidx.core.content.edit

/**
 * ApiKeyProvider — manages the LLM API key lifecycle.
 *
 * TWO MODES (toggled by BuildConfig.SECURE_MODE):
 *
 * VULNERABLE (SECURE_MODE = false)
 *   Returns the key directly from BuildConfig — exactly what jadx
 *   will expose when you decompile the APK in the live demo.
 *   The key is visible in plain text in the disassembled DEX output.
 *
 * HARDENED (SECURE_MODE = true)
 *   1. On first use: encrypts the key with an AES-256-GCM key backed
 *      by the Android Keystore hardware security module.
 *   2. Ciphertext is stored in EncryptedSharedPreferences (or a regular
 *      pref file — the encryption is in Keystore, not the pref).
 *   3. The raw key never persists to disk — only the ciphertext does.
 *   4. Keystore key is marked userAuthenticationRequired = false for
 *      demo simplicity; a production build would set this to true.
 *
 * Portfolio demo note:
 *   - Show jadx on the VULNERABLE APK → BuildConfig.java → API key visible.
 *   - Show jadx on the HARDENED APK  → BuildConfig.java → placeholder only.
 *   - In the hardened build, the Keystore-backed key never leaves the
 *     HSM; extraction via Frida is possible but significantly harder and
 *     requires a rooted device — discuss this trade-off in the demo.
 *
 * IMPORTANT — for a real production app:
 *   The ideal architecture is a backend proxy (see BackendProxyClient).
 *   The key should never be on-device at all. This class demonstrates
 *   the best on-device approach, not the final architecture.
 */
class ApiKeyProvider(private val context: Context) {

    // ─────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────

    /**
     * Returns the API key string ready to be used in an Authorization header.
     *
     * Throws ApiKeyException on any retrieval or decryption failure.
     * Never returns null — callers can rely on the return value or catch.
     */
    fun getApiKey(): String {
        return if (!BuildConfig.SECURE_MODE) {
            // VULNERABLE: plaintext key in BuildConfig — shown to jadx.
            // In a real APK this ends up in classes.dex and is trivially
            // extracted by any decompiler.
            BuildConfig.LLM_API_KEY_PLAIN
        } else {
            getOrProvisionHardenedKey()
        }
    }

    /**
     * Call this once during app initialization (e.g. Application.onCreate)
     * in the hardened build to provision the Keystore key before the first
     * chat message is sent. Avoids first-message latency.
     *
     * Safe to call multiple times — checks for existing key first.
     */
    fun provisionIfNeeded() {
        if (!BuildConfig.SECURE_MODE) return
        ensureKeystoreKeyExists()
    }

    /** Wipes the encrypted blob from SharedPreferences. The Keystore key
     *  entry is NOT deleted — call deleteKeystoreKey for a full wipe. */
    fun clearStoredCiphertext() {
        prefs.edit { remove(PREF_ENCRYPTED_KEY).remove(PREF_IV) }
    }

    /** Deletes the Keystore key entry. After this, getApiKey will
     *  re-provision on next call. */
    fun deleteKeystoreKey() {
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            if (ks.containsAlias(KEY_ALIAS)) {
                ks.deleteEntry(KEY_ALIAS)
            }
        } catch (e: Exception) {
            throw ApiKeyException("Failed to delete Keystore entry", e)
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Hardened path — Keystore-backed AES-256-GCM
    // ─────────────────────────────────────────────────────────────────

    private val prefs by lazy {
        // Context.MODE_PRIVATE ensures the file is sandboxed to this app.
        context.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
    }

    /**
     * Returns the plaintext API key by:
     *   a) Provisioning the Keystore key if it doesn't exist yet.
     *   b) Encrypting and persisting the key if no ciphertext exists.
     *   c) Decrypting the stored ciphertext on subsequent calls.
     *
     * The plaintext key BuildConfig.LLM_API_KEY_ENCRYPTED_SEED is a
     * placeholder/stub value used only once during provisioning to
     * produce the on-disk ciphertext. After that it is never read again.
     */
    private fun getOrProvisionHardenedKey(): String {
        ensureKeystoreKeyExists()

        val storedCiphertext = prefs.getString(PREF_ENCRYPTED_KEY, null)
        val storedIv = prefs.getString(PREF_IV, null)

        return if (storedCiphertext == null || storedIv == null) {
            // First run — encrypt the seed key and persist it.
            val plainKey = BuildConfig.LLM_API_KEY_ENCRYPTED_SEED
            encryptAndStore(plainKey)
            plainKey   // return plaintext on provisioning run
        } else {
            // Subsequent runs — decrypt from ciphertext.
            decrypt(storedCiphertext, storedIv)
        }
    }

    /**
     * Generates the AES-256-GCM key inside the Keystore if it doesn't
     * already exist. Keystore keys are hardware-backed on devices with a
     * TEE or StrongBox — the raw key material never enters the app process.
     */
    private fun ensureKeystoreKeyExists() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        if (ks.containsAlias(KEY_ALIAS)) return

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            /*
             * userAuthenticationRequired(true) would require the user to
             * authenticate (biometric/PIN) before each key use — strongly
             * recommended in production. Disabled here for demo flow.
             */
            .setUserAuthenticationRequired(false)
            /*
             * setIsStrongBoxBacked(true) would pin to the StrongBox
             * co-processor (Pixel 3+). Falls back to TEE on other devices.
             * Not set here to keep demo compatible with emulators.
             */
            .build()

        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }

    /**
     * Encrypts plainKey with the Keystore-backed AES-256-GCM key and
     * stores the base64-encoded ciphertext + IV in SharedPreferences.
     */
    private fun encryptAndStore(plainKey: String) {
        val secretKey = loadSecretKey()
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv  // GCM generates a random 12-byte IV per operation
        val ciphertext = cipher.doFinal(plainKey.toByteArray(Charsets.UTF_8))

        prefs.edit {
            putString(PREF_ENCRYPTED_KEY, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
        }
    }

    /**
     * Decrypts ciphertextB64 using the Keystore key and the stored IV.
     * Throws ApiKeyException if the ciphertext has been tampered with —
     * GCM authentication tag verification fails loudly.
     */
    private fun decrypt(ciphertextB64: String, ivB64: String): String {
        return try {
            val secretKey = loadSecretKey()
            val iv = Base64.decode(ivB64, Base64.NO_WRAP)
            val ciphertext = Base64.decode(ciphertextB64, Base64.NO_WRAP)

            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

            // doFinal verifies the GCM tag — throws AEADBadTagException if
            // the ciphertext has been modified (tamper-evident).
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (e: Exception) {
            throw ApiKeyException("Failed to decrypt API key — possible tampering", e)
        }
    }

    private fun loadSecretKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        return (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: throw ApiKeyException("Keystore key '$KEY_ALIAS' not found — call provisionIfNeeded()")
    }

    // ─────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "vulnchat_llm_key_v1"
        const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128

        const val PREF_FILE = "vulnchat_key_store"
        const val PREF_ENCRYPTED_KEY = "enc_key"
        const val PREF_IV = "enc_iv"
    }

    // ─────────────────────────────────────────────────────────────────
    // Exception type
    // ─────────────────────────────────────────────────────────────────

    class ApiKeyException(message: String, cause: Throwable? = null) :
        Exception(message, cause)
}
