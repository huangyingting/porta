package dev.htun.android

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

internal data class ClientLogEntry(
    val timestampMillis: Long,
    val message: String,
)

internal class ClientLogStore(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun add(message: String) {
        synchronized(LOCK) {
            val entries = entriesUnlocked().takeLast(MAX_ENTRIES - 1).toMutableList()
            entries += ClientLogEntry(
                timestampMillis = System.currentTimeMillis(),
                message = message.replace(Regex("\\s+"), " ").trim().take(MAX_MESSAGE_LENGTH),
            )
            val encoded = JSONArray()
            entries.forEach {
                encoded.put(
                    JSONObject()
                        .put(KEY_TIMESTAMP, it.timestampMillis)
                        .put(KEY_MESSAGE, it.message),
                )
            }
            preferences.edit().putString(KEY_ENTRIES, encoded.toString()).apply()
        }
    }

    fun entries(): List<ClientLogEntry> = synchronized(LOCK) {
        entriesUnlocked()
    }

    private fun entriesUnlocked(): List<ClientLogEntry> {
        val encoded = preferences.getString(KEY_ENTRIES, null) ?: return emptyList()
        return try {
            val entries = JSONArray(encoded)
            buildList {
                for (index in 0 until entries.length()) {
                    val item = entries.getJSONObject(index)
                    add(ClientLogEntry(item.getLong(KEY_TIMESTAMP), item.getString(KEY_MESSAGE)))
                }
            }
        } catch (error: JSONException) {
            Log.e(TAG, "Could not read the client event log", error)
            emptyList()
        }
    }

    fun clear() {
        synchronized(LOCK) {
            preferences.edit().remove(KEY_ENTRIES).apply()
        }
    }

    companion object {
        private const val TAG = "ClientLogStore"
        private const val PREFERENCES = "client_log"
        private const val KEY_ENTRIES = "entries"
        private const val KEY_TIMESTAMP = "timestamp"
        private const val KEY_MESSAGE = "message"
        private const val MAX_ENTRIES = 100
        private const val MAX_MESSAGE_LENGTH = 240
        private val LOCK = Any()
    }
}
