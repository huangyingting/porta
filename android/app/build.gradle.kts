import groovy.json.JsonSlurper
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

fun rustlsPlatformVerifierAar(): File {
    val cargo = providers.environmentVariable("CARGO").orNull
        ?: File(System.getProperty("user.home"), ".cargo/bin/cargo")
            .takeIf(File::isFile)
            ?.absolutePath
        ?: "cargo"
    val metadataText = providers.exec {
        workingDir = rootProject.projectDir.parentFile
        commandLine(
            cargo,
            "metadata",
            "--format-version",
            "1",
            "--filter-platform",
            "aarch64-linux-android",
            "--manifest-path",
            "rust/porta-android/Cargo.toml",
        )
    }.standardOutput.asText.get()
    @Suppress("UNCHECKED_CAST")
    val metadata = JsonSlurper().parseText(metadataText) as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    val packages = metadata.getValue("packages") as List<Map<String, Any?>>
    val dependency = packages.first { it["name"] == "rustls-platform-verifier-android" }
    val manifest = File(dependency.getValue("manifest_path") as String)
    val version = dependency.getValue("version") as String
    return File(
        manifest.parentFile,
        "maven/rustls/rustls-platform-verifier/$version/rustls-platform-verifier-$version.aar",
    )
}

val rustJniLibs = layout.buildDirectory.dir("generated/jniLibs")
val buildRustAndroid by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the Rust Android tunnel library"
    workingDir(rootProject.projectDir.parentFile)
    commandLine(
        "bash",
        "scripts/build-android-rust.sh",
        rustJniLibs.get().asFile.absolutePath,
    )
    inputs.files(
        rootProject.projectDir.parentFile.resolve("rust/Cargo.toml"),
        rootProject.projectDir.parentFile.resolve("rust/Cargo.lock"),
        rootProject.projectDir.parentFile.resolve("rust/porta-android/Cargo.toml"),
        rootProject.projectDir.parentFile.resolve("rust/porta-client/Cargo.toml"),
        rootProject.projectDir.parentFile.resolve("rust/porta-wire/Cargo.toml"),
        rootProject.projectDir.parentFile.resolve("rust/porta-server/vendor/h3/Cargo.toml"),
        rootProject.projectDir.parentFile.resolve("rust/porta-server/vendor/hyper/Cargo.toml"),
        rootProject.projectDir.parentFile.resolve("rust/porta-server/vendor/quinn-proto/Cargo.toml"),
        rootProject.projectDir.parentFile.resolve("scripts/build-android-rust.sh"),
    )
    inputs.dir(rootProject.projectDir.parentFile.resolve("rust/porta-android/src"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("rust/porta-client/src"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("rust/porta-wire/src"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("rust/porta-server/vendor/h3/src"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("rust/porta-server/vendor/hyper/src"))
    inputs.dir(rootProject.projectDir.parentFile.resolve("rust/porta-server/vendor/quinn-proto/src"))
    outputs.dir(rustJniLibs)
}

val signingEnvironment = mapOf(
    "storeFile" to providers.environmentVariable("PORTA_ANDROID_KEYSTORE").orNull,
    "storePassword" to providers.environmentVariable("PORTA_ANDROID_KEYSTORE_PASSWORD").orNull,
    "keyAlias" to providers.environmentVariable("PORTA_ANDROID_KEY_ALIAS").orNull,
    "keyPassword" to providers.environmentVariable("PORTA_ANDROID_KEY_PASSWORD").orNull,
)
val hasEnvironmentSigning = signingEnvironment.values.any { !it.isNullOrBlank() }
val signingConfigRoot = providers.environmentVariable("XDG_CONFIG_HOME").orNull
    ?.takeIf { it.isNotBlank() }?.let(::File) ?: File(System.getProperty("user.home"), ".config")
val signingPropertiesFile = providers.environmentVariable("PORTA_ANDROID_SIGNING_PROPERTIES").orNull
    ?.takeIf { it.isNotBlank() }?.let { rootProject.file(it) }
    ?: rootProject.file(signingConfigRoot.resolve("porta/android-signing/signing.properties"))
val signingProperties = Properties().apply {
    // Partial environment credentials must not silently borrow a local key.
    if (!hasEnvironmentSigning && signingPropertiesFile.isFile) {
        signingPropertiesFile.inputStream().use { load(it) }
    }
}
val releaseSigning = signingEnvironment.mapValues { (name, value) ->
    if (hasEnvironmentSigning) value else signingProperties.getProperty(name)
}
val releaseKeystoreFile = releaseSigning["storeFile"]?.let {
    if (hasEnvironmentSigning) file(it) else signingPropertiesFile.parentFile.resolve(it)
}
val releaseKeystorePassword = releaseSigning["storePassword"]
val releaseKeyAlias = releaseSigning["keyAlias"]
val releaseKeyPassword = releaseSigning["keyPassword"]
val sourceVersion = rootProject.projectDir.parentFile
    .resolve("internal/buildinfo/VERSION")
    .readText()
    .trim()
val applicationVersionName = providers.environmentVariable("PORTA_ANDROID_VERSION_NAME").orNull ?: sourceVersion
val applicationVersionMatch = Regex("""0\.1\.([0-9]{1,3})""").matchEntire(applicationVersionName)
    ?: error("Porta application version must use 0.1.PATCH")
val configuredVersionCode = providers.environmentVariable("PORTA_ANDROID_VERSION_CODE").orNull
val applicationVersionCode = configuredVersionCode?.toIntOrNull() ?: if (configuredVersionCode == null) {
    1000 + applicationVersionMatch.groupValues[1].toInt()
} else {
    error("PORTA_ANDROID_VERSION_CODE must be an integer")
}
require(applicationVersionCode in 1..2_100_000_000) {
    "PORTA_ANDROID_VERSION_CODE must be between 1 and 2100000000"
}
val hasReleaseSigning = releaseSigning.values.all { !it.isNullOrBlank() }
val signingCertificatePin = rootProject.file("signing-certificate.sha256")
val validatePortaReleaseSigning by tasks.registering {
    group = "verification"
    description = "Requires the persistent Porta signing key and checks its certificate identity"
    inputs.file(signingCertificatePin)
    doLast {
        require(hasReleaseSigning) {
            "Release signing is not configured. Restore the persistent Porta key and " +
                "$signingPropertiesFile, or provide all four PORTA_ANDROID signing variables. " +
                "Debug-key fallback is forbidden."
        }
        val storeFile = checkNotNull(releaseKeystoreFile)
        require(storeFile.isFile) { "Porta signing keystore is missing: $storeFile" }
        val store = KeyStore.getInstance(storeFile, checkNotNull(releaseKeystorePassword).toCharArray())
        val alias = checkNotNull(releaseKeyAlias)
        require(store.isKeyEntry(alias)) { "Porta signing alias is missing: $alias" }
        require(store.getKey(alias, checkNotNull(releaseKeyPassword).toCharArray()) is PrivateKey) {
            "Porta signing alias does not contain a private key"
        }
        val certificate = checkNotNull(store.getCertificate(alias)) { "Porta signing certificate is missing" }
        val actual = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val expected = signingCertificatePin.readText().trim().lowercase()
        require(expected.matches(Regex("[0-9a-f]{64}"))) { "Invalid Porta signing certificate pin" }
        require(actual == expected) {
            "Wrong Android signing identity: expected $expected, got $actual. " +
                "Restore the existing key; do not generate a replacement."
        }
    }
}

android {
    namespace = "dev.porta.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.porta.android"
        minSdk = 26
        targetSdk = 35
        versionCode = applicationVersionCode
        versionName = applicationVersionName

        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
    }

    testBuildType = providers.gradleProperty("porta.testBuildType").getOrElse("debug")

    signingConfigs {
        create("release") {
            if (hasReleaseSigning) {
                storeFile = releaseKeystoreFile
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
            signingConfig = signingConfigs.getByName("release")
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

    sourceSets {
        getByName("main") {
            jniLibs.srcDir(rustJniLibs)
        }
    }
}

dependencies {
    implementation(files(rustlsPlatformVerifierAar()))
    implementation("com.squareup.okio:okio:3.9.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation("androidx.activity:activity:1.9.3")
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    testImplementation("junit:junit:4.13.2")
    androidTestCompileOnly(files(
        android.sdkDirectory.resolve("platforms/android-${android.compileSdk}/optional/android.test.base.jar"),
        android.sdkDirectory.resolve("platforms/android-${android.compileSdk}/optional/android.test.runner.jar"),
    ))
}

tasks.named("preBuild").configure {
    dependsOn(buildRustAndroid)
}

tasks.configureEach {
    if (name.contains("Release") && name != "validatePortaReleaseSigning") {
        dependsOn(validatePortaReleaseSigning)
    }
}
