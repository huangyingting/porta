plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val nativeMasqueAar = layout.buildDirectory.file("generated/aar/portamobile.aar")
val buildNativeMasqueAar by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the Go HTTP/3 MASQUE Android bridge"
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        rootProject.projectDir.parentFile.resolve("scripts/build-android-aar.sh").absolutePath,
        nativeMasqueAar.get().asFile.absolutePath,
    )
    inputs.files(
        rootProject.projectDir.parentFile.resolve("go.mod"),
        rootProject.projectDir.parentFile.resolve("go.sum"),
        rootProject.projectDir.parentFile.resolve("scripts/build-android-aar.sh"),
    )
    inputs.dir(rootProject.projectDir.parentFile.resolve("internal"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("mobile/portamobile"))
    outputs.file(nativeMasqueAar)
}

val releaseKeystorePath = providers.environmentVariable("PORTA_ANDROID_KEYSTORE").orNull
val releaseKeystorePassword = providers.environmentVariable("PORTA_ANDROID_KEYSTORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("PORTA_ANDROID_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("PORTA_ANDROID_KEY_PASSWORD").orNull
val hasReleaseSigning = listOf(
    releaseKeystorePath,
    releaseKeystorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }

android {
    namespace = "dev.porta.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.porta.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 15
        versionName = "0.6.1"

        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(releaseKeystorePath!!)
                storePassword = releaseKeystorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = false
        }
    }

    packaging {
        jniLibs.useLegacyPackaging = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(files(nativeMasqueAar))
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("junit:junit:4.13.2")
}

tasks.named("preBuild").configure {
    dependsOn(buildNativeMasqueAar)
}
