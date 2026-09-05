package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLEncoder
import java.util.UUID

class ProfileQrTest {
    @Test
    fun parsesFormEscapingAndUnicodeNameWithoutChangingCredentials() {
        val token = "one two+three/=&?%~"
        val profile = ProfileQr.parse(uri(token = token, name = "家庭 + café"))!!
        assertEquals("https://vpn.example.com:8443", profile.server)
        assertEquals(token, profile.token)
        assertEquals("家庭 + café", profile.name)
    }

    @Test
    fun acceptsAnyParameterOrderAndPercentEncodedKeys() {
        val profile = ProfileQr.parse("porta://profile?token=abc&%73erver=https%3A%2F%2Fvpn.example.com&v=1")!!
        assertEquals("abc", profile.token)
        assertEquals("vpn.example.com", profile.name)
    }

    @Test
    fun defaultsOnlyMissingOrEmptyNames() {
        assertEquals("vpn.example.com", ProfileQr.parse(uri(name = null))!!.name)
        assertEquals("vpn.example.com", ProfileQr.parse(uri(name = ""))!!.name)
        assertEquals("example.com", ProfileQr.parse(uri(server = "https://www.example.com/"))!!.name)
        assertNull(ProfileQr.parse(uri(name = " ")))
    }

    @Test
    fun acceptsHttpsOriginsIncludingIpv6AndPortBoundaries() {
        for (server in listOf("https://example.com", "https://example.com/", "https://example.com:1",
            "https://example.com:65535/", "https://[2001:db8::1]:8443")) {
            assertEquals(server, ProfileQr.parse(uri(server = server))!!.server)
        }
    }

    @Test
    fun rejectsNonHttpsAndNonOriginServers() {
        for (server in listOf("", "http://example.com", "HTTPS://example.com", "example.com",
            "https://user:pass@example.com", "https://example.com/path", "https://example.com//",
            "https://example.com?x=1", "https://example.com#fragment", "https://example.com?",
            "https://example.com#", "https://example.com:0", "https://example.com:65536",
            "https://example.com:-1", "https://example.com:abc", "https://example.com:",
            "https://[::1]:", "https:///example.com",
            " https://example.com", "https://example.com ", "https://example.com\n")) {
            assertNull(server, ProfileQr.parse(uri(server = server)))
        }
    }

    @Test
    fun rejectsUnexpectedUriStructure() {
        val query = "?v=1&server=https%3A%2F%2Fexample.com&token=abc"
        for (prefix in listOf("https://profile", "PORTA://profile", "porta://PROFILE",
            "porta://other", "porta://user@profile", "porta://profile:1", "porta://profile:",
            "porta://profile/", "porta://profile/path", "porta:profile", "porta:///profile",
            "porta://%70rofile")) {
            assertNull(prefix, ProfileQr.parse(prefix + query))
        }
        assertNull(ProfileQr.parse(uri() + "#"))
        assertNull(ProfileQr.parse(uri() + "#anything"))
        assertNull(ProfileQr.parse(" " + uri()))
        assertNull(ProfileQr.parse(uri() + "\n"))
    }

    @Test
    fun rejectsMissingUnknownAndDuplicateParameters() {
        for (query in listOf("", "v=1", "server=https%3A%2F%2Fexample.com&token=abc",
            "v=1&token=abc", "v=1&server=https%3A%2F%2Fexample.com")) {
            assertNull(ProfileQr.parse("porta://profile?$query"))
        }
        for (suffix in listOf("&v=1", "&token=def", "&server=https%3A%2F%2Fother.com", "&name=other",
            "&%74oken=def", "&clientId=remote", "&client_id=remote", "&device_id=remote", "&android_id=remote", "&autoConnect=true",
            "&insecure=true", "&x=1", "&", "&&", "&=x", "&broken")) {
            assertNull(suffix, ProfileQr.parse(uri(name = "Test") + suffix))
        }
        for (version in listOf("", "0", "2", "01", "1.0", " 1", "1 ")) {
            assertNull(ProfileQr.parse(uri().replace("v=1", "v=${encode(version)}")))
        }
    }

    @Test
    fun rejectsMalformedEscapesUtf8AndRawNonAscii() {
        for (encoded in listOf("%", "%1", "%GG", "%0x", "%80", "%FF", "%C0%AF", "%C1%81",
            "%C3", "%E2%82", "%E2%28%A1", "%ED%A0%80", "%F4%90%80%80", "%F5%80%80%80")) {
            assertNull(encoded, ProfileQr.parse(uri() + "&name=$encoded"))
        }
        assertNull(ProfileQr.parse(uri() + "&name=café"))
        assertNull(ProfileQr.parse(uri() + "&name=\uD800"))
        assertNull(ProfileQr.parse(uri() + "&%FF=value"))
    }

    @Test
    fun boundsTokenAndRejectsNonPrintableOrTrimmedTokens() {
        assertEquals("x".repeat(512), ProfileQr.parse(uri(token = "x".repeat(512)))!!.token)
        assertNotNull(ProfileQr.parse(uri(token = "!")))
        assertNull(ProfileQr.parse(uri(token = "x".repeat(513))))
        for (token in listOf("", " ", " a", "a ", "\ta", "a\n", "a\rb", "a\u0000b",
            "a\u001fb", "a\u007fb", "aéb")) {
            assertNull(ProfileQr.parse(uri(token = token)))
        }
        assertEquals("a  b", ProfileQr.parse(uri(token = "a  b"))!!.token)
    }

    @Test
    fun boundsNameInUtf8BytesAndRejectsControlsAndSurroundingWhitespace() {
        for (name in listOf("n".repeat(80), "é".repeat(40), "😀".repeat(20))) {
            assertEquals(name, ProfileQr.parse(uri(name = name))!!.name)
        }
        for (name in listOf("n".repeat(81), "é".repeat(41), "😀".repeat(21), " a", "a ",
            "\u2003a", "a\u00a0", "a\tb", "a\nb", "a\u007fb", "a\u0085b", "a\u009fb")) {
            assertNull(ProfileQr.parse(uri(name = name)))
        }
    }

    @Test
    fun boundsServerAndRawPayloadIndependently() {
        val longestServer = "https://" + "a".repeat(504)
        assertEquals(512, longestServer.length)
        assertNotNull(ProfileQr.parse(uri(server = longestServer)))
        assertNull(ProfileQr.parse(uri(server = longestServer + "a")))
        fun rawPayload(length: Int): String {
            var name = "n".repeat(78)
            var base = uri(server = longestServer, token = "a".repeat(512), name = name)
            if ((length - base.length) % 2 != 0) {
                name += "n"
                base = uri(server = longestServer, token = "a".repeat(512), name = name)
            }
            val escapes = (length - base.length) / 2
            assertTrue(escapes in 0..512)
            return base.replace("token=" + "a".repeat(512), "token=" + "%61".repeat(escapes) + "a".repeat(512 - escapes))
        }
        val maximum = rawPayload(2048)
        assertEquals(2048, maximum.length)
        assertNotNull(ProfileQr.parse(maximum))
        val tooLong = rawPayload(2049)
        assertEquals(2049, tooLong.length)
        assertNull(ProfileQr.parse(tooLong))
        assertNull(ProfileQr.parse(null))
        assertNull(ProfileQr.parse(""))
        assertNull(ProfileQr.parse("  "))
    }

    @Test
    fun eachAcceptedScanCreatesOnlyALocalProfileIdAndNeverEnablesAutoConnect() {
        val first = qrProfileDraft(true, uri(name = "Test"))!!
        val second = qrProfileDraft(true, uri(name = "Test"))!!
        assertNotEquals(first.id, second.id)
        assertNotNull(UUID.fromString(first.id))
        assertTrue(VpnProfile::class.java.declaredFields.none { it.name == "clientId" })
        assertEquals(first.server, second.server)
        assertEquals(first.token, second.token)
        assertFalse(first.autoConnect)
        assertFalse(second.autoConnect)
        assertEquals("Test", first.name)
        assertEquals("example-token", first.token)
    }

    @Test
    fun cancellationAndInvalidResultsDoNotCreateDrafts() {
        assertNull(qrProfileDraft(false, uri()))
        assertNull(qrProfileDraft(false, null))
        assertNull(qrProfileDraft(true, null))
        assertNull(qrProfileDraft(true, "https://example.com"))
    }

    private fun uri(
        server: String = "https://vpn.example.com:8443",
        token: String = "example-token",
        name: String? = null,
    ): String = "porta://profile?v=1&server=${encode(server)}&token=${encode(token)}" +
        if (name == null) "" else "&name=${encode(name)}"

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")
}
