plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val nativeMasqueAar = layout.buildDirectory.file("generated/aar/htunmobile.aar")
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
    )
    inputs.dir(rootProject.projectDir.parentFile.resolve("internal"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("mobile/htunmobile"))
    outputs.file(nativeMasqueAar)
}

val releaseKeystorePath = providers.environmentVariable("HTUN_ANDROID_KEYSTORE").orNull
val releaseKeystorePassword = providers.environmentVariable("HTUN_ANDROID_KEYSTORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("HTUN_ANDROID_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("HTUN_ANDROID_KEY_PASSWORD").orNull
val hasReleaseSigning = listOf(
    releaseKeystorePath,
    releaseKeystorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }

android {
    namespace = "dev.htun.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.htun.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 6
        versionName = "0.3.0"

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
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
        }
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
