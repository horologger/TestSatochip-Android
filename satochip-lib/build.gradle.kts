plugins {
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.jetbrainsKotlinAndroid)
    alias(libs.plugins.kotlin.serialization) // Assuming this is needed based on app module
}

android {
    namespace = "org.satochip.satochiplib" // Define a namespace for the library
    compileSdk = 34 // Match your app's SDK

    defaultConfig {
        minSdk = 24 // Match your app's minSdk
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
     buildFeatures {
         // Enable features if needed, e.g., compose = true
     }
    packaging { // Add packaging options if needed, similar to app module
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // Add any dependencies that satochip-lib itself requires
    // These are guesses based on the app module, adjust as needed
    implementation(libs.kotlinx.serialization.json)
    implementation("org.bitcoinj:bitcoinj-core:0.16.2")

    // Add other necessary AndroidX or Kotlin libraries if the lib uses them directly
    // implementation(libs.androidx.core.ktx)
} 