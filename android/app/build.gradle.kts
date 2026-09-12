plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Supplied by the build pipeline. Empty in a local build, and the app then
// asks the user for their own OAuth client instead of failing.
val googleClientId: String = System.getenv("ZAPASSKA_GOOGLE_CLIENT_ID") ?: ""

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

    buildTypes {
        release {
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
