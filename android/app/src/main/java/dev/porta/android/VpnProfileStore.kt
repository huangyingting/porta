package dev.porta.android

import android.annotation.SuppressLint
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal data class VpnProfile(
    val id: String,
    val name: String,
    val server: String,
    val token: String,
    val autoConnect: Boolean,
)

internal class VpnProfileStore(private val context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun profiles(): List<VpnProfile> = readProfiles() ?: emptyList()

    private fun readProfiles(): List<VpnProfile>? {
        val encoded = preferences.getString(KEY_PROFILES, null) ?: return emptyList()
        return try {
            val entries = JSONArray(encoded)
            for (index in 0 until entries.length()) {
                val entry = entries.getJSONObject(index)
                if (entry.optInt(KEY_VERSION, LEGACY_PROFILE_VERSION) == LEGACY_PROFILE_VERSION) {
                    clearLegacyProfiles()
                    return emptyList()
                }
            }
            val profiles = mutableListOf<VpnProfile>()
            for (index in 0 until entries.length()) {
                val entry = entries.getJSONObject(index)
                val profile = decode(entry) ?: return null
                profiles += profile
            }
            profiles
        } catch (error: JSONException) {
            Log.e(TAG, "Could not read VPN profiles", error)
            null
        }
    }

    @SuppressLint("ApplySharedPref")
    private fun clearLegacyProfiles() {
        Log.w(TAG, "Clearing unsupported legacy VPN profiles")
        preferences.edit()
            .remove(KEY_PROFILES)
            .remove(KEY_SELECTED_PROFILE)
            .commit()
    }

    fun save(profile: VpnProfile): Boolean {
        val stored = readProfiles() ?: return false
        val updated = stored.filterNot { it.id == profile.id }.toMutableList()
        if (profile.autoConnect) {
            for (index in updated.indices) {
                updated[index] = updated[index].copy(autoConnect = false)
            }
        }
        updated += profile
        return write(updated.sortedBy { it.name.lowercase() })
    }

    fun delete(profileId: String): Boolean {
        val stored = readProfiles() ?: return false
        return write(stored.filterNot { it.id == profileId })
    }

    fun selectedProfileId(): String? = preferences.getString(KEY_SELECTED_PROFILE, null)

    fun select(profileId: String?) {
        preferences.edit().apply {
            if (profileId == null) remove(KEY_SELECTED_PROFILE) else putString(KEY_SELECTED_PROFILE, profileId)
        }.apply()
    }

    @SuppressLint("ApplySharedPref")
    private fun write(profiles: List<VpnProfile>): Boolean {
        return try {
            val entries = JSONArray()
            profiles.forEach { entries.put(encode(it)) }
            preferences.edit().putString(KEY_PROFILES, entries.toString()).commit()
        } catch (error: GeneralSecurityException) {
            Log.e(TAG, "Could not encrypt VPN profiles", error)
            false
        } catch (error: IOException) {
            Log.e(TAG, "Could not encrypt VPN profiles", error)
            false
        }
    }

    private fun encode(profile: VpnProfile): JSONObject {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
        cipher.updateAAD(ProfileTokenFormat.associatedData(profile.id, profile.server))
        val encrypted = cipher.doFinal(profile.token.toByteArray(Charsets.UTF_8))
        return JSONObject()
            .put(KEY_VERSION, ProfileTokenFormat.VERSION)
            .put(KEY_ID, profile.id)
            .put(KEY_NAME, profile.name)
            .put(KEY_SERVER, profile.server)
            .put(KEY_AUTO_CONNECT, profile.autoConnect)
            .put(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .put(KEY_TOKEN, Base64.encodeToString(encrypted, Base64.NO_WRAP))
    }

    private fun decode(entry: JSONObject): VpnProfile? {
        return try {
            if (entry.getInt(KEY_VERSION) != ProfileTokenFormat.VERSION) {
                throw JSONException("Unsupported profile storage version")
            }
            val profile = VpnProfile(
                id = entry.getString(KEY_ID),
                name = entry.getString(KEY_NAME),
                server = entry.getString(KEY_SERVER),
                token = "",
                autoConnect = entry.optBoolean(KEY_AUTO_CONNECT),
            )
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                encryptionKey(),
                GCMParameterSpec(128, Base64.decode(entry.getString(KEY_IV), Base64.NO_WRAP)),
            )
            cipher.updateAAD(ProfileTokenFormat.associatedData(profile.id, profile.server))
            profile.copy(
                token = cipher.doFinal(Base64.decode(entry.getString(KEY_TOKEN), Base64.NO_WRAP))
                    .toString(Charsets.UTF_8),
            )
        } catch (error: GeneralSecurityException) {
            Log.e(TAG, "Could not decrypt a VPN profile", error)
            null
        } catch (error: IOException) {
            Log.e(TAG, "Could not decrypt a VPN profile", error)
            null
        } catch (error: JSONException) {
            Log.e(TAG, "Could not decrypt a VPN profile", error)
            null
        } catch (error: IllegalArgumentException) {
            Log.e(TAG, "Could not decrypt a VPN profile", error)
            null
        }
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

    companion object {
        private const val TAG = "VpnProfileStore"
        private const val PREFERENCES = "vpn_profiles"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "porta-profile-token-v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_PROFILES = "profiles"
        private const val KEY_SELECTED_PROFILE = "selected_profile"
        private const val KEY_ID = "id"
        private const val KEY_NAME = "name"
        private const val KEY_SERVER = "server"
        private const val KEY_VERSION = "version"
        private const val KEY_AUTO_CONNECT = "auto_connect"
        private const val KEY_IV = "iv"
        private const val KEY_TOKEN = "token"
        private const val LEGACY_PROFILE_VERSION = 1
    }
}

internal fun profileName(server: String): String = try {
    java.net.URI(server).host?.removePrefix("www.")?.takeIf { it.isNotBlank() } ?: "VPN server"
} catch (_: Exception) {
    "VPN server"
}

internal fun isHttpsOrigin(server: String): Boolean = try {
    val uri = java.net.URI(server)
    uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null &&
        uri.rawAuthority?.endsWith(":") != true &&
        (uri.port == -1 || uri.port in 1..65_535) &&
        (uri.path.isNullOrEmpty() || uri.path == "/") && uri.query == null && uri.fragment == null
} catch (_: java.net.URISyntaxException) {
    false
}

internal fun isValidToken(token: String): Boolean =
    token.isNotBlank() && token.all { it in ' '..'~' }
