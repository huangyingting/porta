package dev.porta.android

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import portamobile.Portamobile
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

internal class DeviceIdentityUnavailableException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

internal data class DeviceProof(
    val publicKey: String,
    val timestamp: String,
    val nonce: String,
    val signature: String,
)

internal data class AndroidDeviceIdentity(
    val id: String,
    val name: String,
    val publicKey: String,
    private val privateKey: PrivateKey,
    val hardwareBacked: Boolean,
) {
    fun proof(token: String, method: String, path: String): DeviceProof {
        try {
            val timestamp = (System.currentTimeMillis() / 1000L).toString()
            val nonceBytes = ByteArray(16).also(SecureRandom()::nextBytes)
            val nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes)
            val message = Portamobile.deviceProofMessage(
                token, method, path, id, name, timestamp, nonce,
            )
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(privateKey)
                update(message)
                sign()
            }
            return DeviceProof(
                publicKey = publicKey,
                timestamp = timestamp,
                nonce = nonce,
                signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signature),
            )
        } catch (error: Exception) {
            throw DeviceIdentityUnavailableException("Could not sign the device request", error)
        }
    }
}

internal fun androidDeviceIdentity(context: Context): AndroidDeviceIdentity {
    try {
        val privateKey = loadOrCreateSigningKey(context)
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val certificate = store.getCertificate(KEY_ALIAS)
            ?: throw DeviceIdentityUnavailableException("The device security key has no public certificate")
        val encodedPublicKey = certificate.publicKey.encoded
        val publicKey = Base64.getUrlEncoder().withoutPadding().encodeToString(encodedPublicKey)
        val id = Portamobile.deviceID(encodedPublicKey)
        val name = deviceIdentityFromNames(
            readDeviceName = {
                Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)
            },
            model = Build.MODEL,
            reportFallback = { message ->
                ClientLogStore(context).add("$message; Android API ${Build.VERSION.SDK_INT}")
            },
        )
        return AndroidDeviceIdentity(id, name, publicKey, privateKey, isHardwareBacked(privateKey))
    } catch (error: DeviceIdentityUnavailableException) {
        throw error
    } catch (error: Exception) {
        throw DeviceIdentityUnavailableException("Could not load the device security key", error)
    }
}

private fun loadOrCreateSigningKey(context: Context): PrivateKey {
    val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    if (!store.containsAlias(KEY_ALIAS)) {
        val preferStrongBox = Build.VERSION.SDK_INT >= 28 &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        try {
            generateSigningKey(preferStrongBox)
        } catch (error: StrongBoxUnavailableException) {
            if (!preferStrongBox) throw error
            generateSigningKey(false)
        }
    }
    val key = store.getKey(KEY_ALIAS, null)
    return key as? PrivateKey
        ?: throw DeviceIdentityUnavailableException("The saved device security key is invalid")
}

private fun generateSigningKey(strongBox: Boolean) {
    val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(false)
        .apply {
            if (Build.VERSION.SDK_INT >= 28 && strongBox) {
                setIsStrongBoxBacked(true)
            }
        }
        .build()
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
        initialize(spec)
        generateKeyPair()
    }
}

@Suppress("DEPRECATION")
private fun isHardwareBacked(privateKey: PrivateKey): Boolean = try {
    KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
        .getKeySpec(privateKey, KeyInfo::class.java)
        .isInsideSecureHardware
} catch (_: Exception) {
    false
}

internal fun deviceIdentityFromNames(
    readDeviceName: () -> String?,
    model: String?,
    reportFallback: (String) -> Unit,
): String {
    var reason = "missing or unsupported"
    val name = try {
        readDeviceName()
    } catch (_: SecurityException) {
        reason = "access denied"
        null
    }
    deviceIdentityFromName(name)?.let { return it }
    val modelName = deviceIdentityFromName(model?.takeUnless { it.equals("unknown", ignoreCase = true) })
    reportFallback(
        if (modelName != null) "Device name $reason; using model name"
        else "Device name $reason and model name unavailable; using android",
    )
    return modelName ?: "android"
}

internal fun deviceIdentityFromName(name: String?): String? = name
    ?.replace(Regex("[^A-Za-z0-9._-]+"), "-")
    ?.trim('-', '.', '_')
    ?.take(64)
    ?.takeIf { it.isNotEmpty() }

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val KEY_ALIAS = "porta-device-auth-v1"
