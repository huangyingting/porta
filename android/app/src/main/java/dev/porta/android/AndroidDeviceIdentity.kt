package dev.porta.android

import android.annotation.SuppressLint
import android.content.Context
import android.provider.Settings
import java.util.Base64

internal class DeviceIdentityUnavailableException(cause: Throwable? = null) :
    Exception("Android device ID is unavailable", cause)

// SSAID is app-scoped on API 26+; it labels enrollment, not hardware authenticity.
@SuppressLint("HardwareIds")
internal fun androidDeviceIdentity(context: Context): String {
    val value = try {
        Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
    } catch (error: SecurityException) {
        throw DeviceIdentityUnavailableException(error)
    }
    return deviceIdentityFromAndroidId(value) ?: throw DeviceIdentityUnavailableException()
}

internal fun deviceIdentityFromAndroidId(value: String?): String? {
    if (value == null || !value.matches(Regex("[0-9a-fA-F]{1,16}")) || value.all { it == '0' }) {
        return null
    }
    val hex = value.padStart(16, '0')
    val bytes = ByteArray(8) { index -> hex.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    return "a-" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
