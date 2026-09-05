package dev.porta.android

import java.net.URI
import java.net.URISyntaxException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.UUID

internal class ProfileQr private constructor(
    val server: String,
    val token: String,
    val name: String,
) {
    fun newProfile(): VpnProfile = VpnProfile(
        id = UUID.randomUUID().toString(),
        name = name,
        server = server,
        token = token,
        autoConnect = false,
    )

    companion object {
        fun parse(payload: String?): ProfileQr? {
            if (payload == null || payload.length !in 1..2048 || payload.any { it.code > 127 }) return null
            val uri = try {
                URI(payload)
            } catch (_: URISyntaxException) {
                return null
            }
            if (uri.scheme != "porta" || uri.rawAuthority != "profile" ||
                uri.rawPath != "" || uri.rawFragment != null
            ) return null
            val query = uri.rawQuery ?: return null
            val parameters = mutableMapOf<String, String>()
            for (part in query.split('&')) {
                val separator = part.indexOf('=')
                if (separator <= 0) return null
                val key = decodeForm(part.substring(0, separator)) ?: return null
                if (key !in setOf("v", "server", "token", "name") || key in parameters) return null
                parameters[key] = decodeForm(part.substring(separator + 1)) ?: return null
            }
            if (parameters["v"] != "1") return null
            val server = parameters["server"] ?: return null
            val token = parameters["token"] ?: return null
            val name = parameters["name"].orEmpty()
            if (server.toByteArray(Charsets.UTF_8).size > 512 || !isHttpsOrigin(server)) return null
            if (token.length !in 1..512 || !isValidToken(token) || token != token.trim()) return null
            if (name.toByteArray(Charsets.UTF_8).size > 80 || name != name.trim() ||
                name.any { Character.isISOControl(it) }
            ) return null
            return ProfileQr(server, token, name.ifEmpty { profileName(server) })
        }

        private fun decodeForm(value: String): String? {
            val bytes = ByteArray(value.length)
            var size = 0
            var index = 0
            while (index < value.length) {
                when (val character = value[index++]) {
                    '+' -> bytes[size++] = ' '.code.toByte()
                    '%' -> {
                        if (index + 1 >= value.length) return null
                        val high = value[index++].digitToIntOrNull(16) ?: return null
                        val low = value[index++].digitToIntOrNull(16) ?: return null
                        bytes[size++] = ((high shl 4) or low).toByte()
                    }
                    else -> bytes[size++] = character.code.toByte()
                }
            }
            return try {
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes, 0, size)).toString()
            } catch (_: CharacterCodingException) {
                null
            }
        }
    }
}

internal fun qrProfileDraft(resultAccepted: Boolean, payload: String?): VpnProfile? =
    if (resultAccepted) ProfileQr.parse(payload)?.newProfile() else null
