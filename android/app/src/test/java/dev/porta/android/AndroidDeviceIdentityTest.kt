package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.util.Base64

class AndroidDeviceIdentityTest {
    @Test
    fun usesOnlyTheOsProvidedIdentifierWithAStableNamespace() {
        assertEquals("a-ASNFZ4mrze8", deviceIdentityFromAndroidId("0123456789abcdef"))
        assertEquals("a-ASNFZ4mrze8", deviceIdentityFromAndroidId("0123456789ABCDEF"))
        repeat(10) {
            assertEquals("a-ASNFZ4mrze8", deviceIdentityFromAndroidId("0123456789abcdef"))
        }
        assertNotEquals(deviceIdentityFromAndroidId("1234"), deviceIdentityFromAndroidId("5678"))
    }

    @Test
    fun unavailableOrInvalidIdsNeverGenerateAFallback() {
        for (value in listOf(null, "", "0", "0000000000000000", "unknown", "Pixel-10-Pro",
            "123456789abcdef01", "1234 ", " 1234", "1234\n", "-1234", "abcd-1234")) {
            assertNull(value, deviceIdentityFromAndroidId(value))
        }
    }

    @Test
    fun acceptsTheDocumentedUnsigned64BitHexRange() {
        assertEquals("a-AAAAAAAAAAE", deviceIdentityFromAndroidId("1"))
        assertEquals("a-__________8", deviceIdentityFromAndroidId("ffffffffffffffff"))
        assertEquals(deviceIdentityFromAndroidId("1"), deviceIdentityFromAndroidId("0000000000000001"))
    }

    @Test
    fun compactEncodingPreservesEveryBitAndHasFixedLength() {
        for (value in listOf("1", "0123456789abcdef", "8000000000000000", "ffffffffffffffff")) {
            val identity = requireNotNull(deviceIdentityFromAndroidId(value))
            assertEquals(13, identity.length)
            assertTrue(identity.matches(Regex("a-[A-Za-z0-9_-]{11}")))
            val decoded = Base64.getUrlDecoder().decode(identity.removePrefix("a-"))
            assertEquals(8, decoded.size)
            assertEquals(value.padStart(16, '0'), BigInteger(1, decoded).toString(16).padStart(16, '0'))
        }
    }
}
