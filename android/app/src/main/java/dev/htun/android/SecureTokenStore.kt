package dev.htun.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class StoredTunnelConfig(
    val server: String,
    val clientId: String,
    val token: String,
)

internal class SecureTokenStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun save(server: String, clientId: String, token: String): Boolean {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
            cipher.updateAAD(associatedData(server, clientId))
            val encrypted = cipher.doFinal(token.toByteArray(Charsets.UTF_8))
            preferences.edit()
                .putString(KEY_SERVER, server)
                .putString(KEY_CLIENT_ID, clientId)
                .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .putString(KEY_TOKEN, Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .apply()
            true
        } catch (_: GeneralSecurityException) {
            clear()
            false
        }
    }

    fun load(): StoredTunnelConfig? {
        val server = preferences.getString(KEY_SERVER, null) ?: return null
        val clientId = preferences.getString(KEY_CLIENT_ID, null) ?: return null
        val iv = preferences.getString(KEY_IV, null) ?: return null
        val encrypted = preferences.getString(KEY_TOKEN, null) ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                encryptionKey(),
                GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)),
            )
            cipher.updateAAD(associatedData(server, clientId))
            val token = cipher.doFinal(Base64.decode(encrypted, Base64.NO_WRAP))
                .toString(Charsets.UTF_8)
            StoredTunnelConfig(server, clientId, token)
        } catch (_: GeneralSecurityException) {
            clear()
            null
        } catch (_: IllegalArgumentException) {
            clear()
            null
        }
    }

    fun clear() {
        preferences.edit().clear().apply()
    }

    private fun encryptionKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build(),
            )
            generateKey()
        }
    }

    private fun associatedData(server: String, clientId: String): ByteArray =
        "$server\n$clientId".toByteArray(Charsets.UTF_8)

    companion object {
        private const val PREFERENCES = "secure_tunnel"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "htun-token-v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_SERVER = "server"
        private const val KEY_CLIENT_ID = "client_id"
        private const val KEY_IV = "iv"
        private const val KEY_TOKEN = "token"
    }
}
