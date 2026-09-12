plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Supplied by the build pipeline. Empty in a local build, and the app then
// asks the user for their own OAuth client instead of failing.
// Identifiers and paths cannot hold meaningful whitespace, so they are
// trimmed. Passwords can, so only the line endings a paste leaves behind are
// stripped from those.
fun env(name: String): String = (System.getenv(name) ?: "").trim()

fun secret(name: String): String =
    (System.getenv(name) ?: "").replace("\r", "").replace("\n", "")

val googleClientId: String = env("ZAPASSKA_GOOGLE_CLIENT_ID")

// Google ties an Android OAuth client to the signing certificate, so release
// builds have to use one fixed keystore. Without it only a debug build is
// possible, and its certificate differs on every machine.
val keystorePath: String = env("ANDROID_KEYSTORE_PATH")

android {
    namespace = "com.zapasska"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.zapasska"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        buildConfigField("String", "GOOGLE_CLIENT_ID", "\"$googleClientId\"")

        // Google redirects an Android OAuth client back to the reversed id.
        val reversed = googleClientId.substringBefore(".apps.googleusercontent.com")
            .let { if (it.isEmpty()) "com.zapasska.oauth" else "com.googleusercontent.apps.$it" }
        manifestPlaceholders["oauthScheme"] = reversed
        buildConfigField("String", "OAUTH_REDIRECT_SCHEME", "\"$reversed\"")
    }

    signingConfigs {
        if (keystorePath.isNotEmpty()) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = secret("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = env("ANDROID_KEY_ALIAS")
                keyPassword = secret("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            if (keystorePath.isNotEmpty()) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"),
                          "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")

    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.ui:ui-tooling-preview")

    // scrypt: the platform has no implementation of it.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // Android stubs org.json for unit tests, so give them a real one.
    testImplementation("org.json:json:20240303")
    testImplementation("junit:junit:4.13.2")
}
