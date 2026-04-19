# ── VulnChat ProGuard / R8 rules ──────────────────────────────────────────────

# ── OkHttp + Okio ─────────────────────────────────────────────────────────────
-dontwarn okhttp3.**
-dontwarn okio.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# ── Kotlin coroutines ─────────────────────────────────────────────────────────
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# ── Kotlin serialization (if added later) ─────────────────────────────────────
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

# ── Security classes — keep names for Keystore alias lookups ──────────────────
# R8 must not rename ApiKeyProvider or its companion constants — the Keystore
# alias string "vulnchat_llm_key_v1" is matched at runtime by the Android
# Keystore service, so renaming the class that holds it would cause confusion
# (the actual alias is a string literal, but keeping the class readable helps
# debugging and avoids accidental minification of the string constants).
-keep class com.vulnchat.security.ApiKeyProvider { *; }
-keep class com.vulnchat.security.ApiKeyProvider$* { *; }
-keep class com.vulnchat.security.InputFilter { *; }
-keep class com.vulnchat.security.InputFilter$FilterResult { *; }
-keep class com.vulnchat.security.InputFilter$FilterResult$* { *; }

# ── Network layer — keep exception types for typed catch blocks ───────────────
-keep class com.vulnchat.network.LlmNetworkException { *; }
-keep class com.vulnchat.network.LlmApiException { *; }
-keep class com.vulnchat.network.LlmParseException { *; }
-keep class com.vulnchat.network.RateLimitException { *; }
-keep class com.vulnchat.network.ProxyAuthException { *; }

# ── Sealed classes / data classes used in Flow emissions ──────────────────────
-keep class com.vulnchat.network.StreamEvent { *; }
-keep class com.vulnchat.network.StreamEvent$* { *; }
-keep class com.vulnchat.network.ChatMessage { *; }
-keep class com.vulnchat.network.ChatMessage$Role { *; }

# ── Portfolio demo note ───────────────────────────────────────────────────────
# Run:  ./gradlew assembleHardenedRelease
# Then: jadx -d out app-hardened-release.apk
# Show: BuildConfig.java has only "MISSING_KEY" placeholder (secrets.properties
#       not committed), class names are minified, and no API key is visible.
# Contrast with: ./gradlew assembleVulnerableDebug → key appears in BuildConfig.
