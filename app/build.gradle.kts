import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// ── Load secrets from secrets.properties (never committed to git) ──────────
// Copy secrets.properties.template to secrets.properties and fill in your key.
val secretsFile = rootProject.file("secrets.properties")
val secrets = Properties().apply {
    if (secretsFile.exists()) load(secretsFile.inputStream())
}

android {
    namespace   = "com.weijia.vulnchat"
    compileSdk  = 36

    defaultConfig {
        applicationId   = "com.weijia.vulnchat"
        minSdk          = 26          // Keystore AES-GCM reliable from API 26
        targetSdk       = 36
        versionCode     = 1
        versionName     = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables.useSupportLibrary = true

        // ── Security mode toggle ─────────────────────────────────────────
        // false → VULNERABLE build (demo jadx / injection attacks)
        // true  → HARDENED  build (demo defenses)
        buildConfigField("boolean", "SECURE_MODE", "false")

        // ── API key fields ───────────────────────────────────────────────
        // Both read from secrets.properties — see secrets.properties.template
        val plainKey     = secrets.getProperty("LLM_API_KEY", "MISSING_KEY")
        val encryptedKey = secrets.getProperty("LLM_API_KEY", "MISSING_KEY")
        buildConfigField("String", "LLM_API_KEY_PLAIN",           "\"$plainKey\"")
        buildConfigField("String", "LLM_API_KEY_ENCRYPTED_SEED",  "\"$encryptedKey\"")
    }

    // ── Product flavors — install both APKs side-by-side on demo device ──
    flavorDimensions += "security"
    productFlavors {
        create("vulnerable") {
            dimension          = "security"
            buildConfigField("boolean", "SECURE_MODE", "false")
            applicationIdSuffix = ".vulnerable"
            versionNameSuffix  = "-vulnerable"
            resValue("string", "app_name", "VulnChat (Vulnerable)")
        }
        create("hardened") {
            dimension          = "security"
            buildConfigField("boolean", "SECURE_MODE", "true")
            applicationIdSuffix = ".hardened"
            versionNameSuffix  = "-hardened"
            resValue("string", "app_name", "VulnChat (Hardened)")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled   = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Never ship the vulnerable flavor to release —
            // CI should enforce this via a build check.
            signingConfig = signingConfigs.findByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
            isDebuggable        = true
        }
    }

    buildFeatures {
        compose      = true
        buildConfig  = true     // required for BuildConfig.SECURE_MODE
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // ── AndroidX ──────────────────────────────────────────────────────
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.activity.compose)

    // ── Compose ───────────────────────────────────────────────────────
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)

    // ── Coroutines ────────────────────────────────────────────────────
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.coroutines.core)

    // ── Networking ────────────────────────────────────────────────────
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)

    // ── Security ──────────────────────────────────────────────────────
    // Android Keystore API is part of the platform (no extra dep).
    // EncryptedSharedPreferences is available via security-crypto.
    implementation(libs.androidx.security.crypto)

    // ── Debug tooling ─────────────────────────────────────────────────
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    // ── Tests ─────────────────────────────────────────────────────────
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit.ext)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
}
