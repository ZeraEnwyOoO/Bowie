plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val bowieAbis = (project.findProperty("bowieAbis") as String?)
    ?.split(",")
    ?.map { it.trim() }
    ?.filter { it.isNotEmpty() }
    ?: listOf("arm64-v8a")

val releaseKeystore = providers.environmentVariable("BOWIE_RELEASE_KEYSTORE").orNull
val releaseStorePassword = providers.environmentVariable("BOWIE_RELEASE_STORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("BOWIE_RELEASE_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("BOWIE_RELEASE_KEY_PASSWORD").orNull
val hasReleaseSigning = listOf(
    releaseKeystore, releaseStorePassword, releaseKeyAlias, releaseKeyPassword
).all { !it.isNullOrBlank() }

android {
    namespace = "org.bowie"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.bowie"
        minSdk = 28
        targetSdk = 35
        versionCode = 2
        versionName = "0.1.1"
        ndk { abiFilters.addAll(bowieAbis) }
        externalNativeBuild {
            cmake { arguments += "-DBOWIE_ANDROID_DEPS=${providers.gradleProperty("bowieDeps").orNull ?: ""}" }
        }
    }

    flavorDimensions += "audience"
    productFlavors {
        create("full") {
            dimension = "audience"
        }
        create("guest") {
            dimension = "audience"
            applicationIdSuffix = ".guest"
            versionNameSuffix = "-guest"
        }
    }

    signingConfigs {
        create("release") {
            if (hasReleaseSigning) {
                storeFile = file(releaseKeystore!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake { path = file("../CMakeLists.txt"); version = "3.22.1" }
    }
}

dependencies {
    implementation("com.google.android.material:material:1.12.0")
}

tasks.configureEach {
    if (name.contains("Release", ignoreCase = true)) {
        doFirst {
            check(hasReleaseSigning) {
                "Release builds require BOWIE_RELEASE_KEYSTORE, BOWIE_RELEASE_STORE_PASSWORD, " +
                    "BOWIE_RELEASE_KEY_ALIAS, and BOWIE_RELEASE_KEY_PASSWORD."
            }
        }
    }
}
