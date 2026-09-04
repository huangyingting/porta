package dev.porta.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketFilterTest {
    @Test
    fun derivesReadableProfileNamesAndSafeClientIds() {
        assertTrue(profileName("https://vpn.example.com:8443") == "vpn.example.com")
        assertTrue(profileName("invalid") == "VPN server")
        assertTrue("Pixel 10 Pro".safeClientId() == "Pixel-10-Pro")
        assertTrue("***".safeClientId() == "android")
    }

    @Test
    fun formatsTrafficRatesAndTotals() {
        assertTrue(formatDataRate(0) == "0 B/s")
        assertTrue(formatDataRate(1536) == "1.5 KB/s")
        assertTrue(formatDataSize(2 * 1024 * 1024) == "2.0 MB")
    }

    @Test
    fun reservesHttp2LaneZeroForDns() {
        val packet = ByteArray(28)
        packet[0] = 0x45
        packet[3] = packet.size.toByte()
        packet[9] = 17
        packet[12] = 10
        packet[13] = 66
        packet[15] = 2
        packet[16] = 1
        packet[17] = 1
        packet[18] = 1
        packet[19] = 1
        packet[20] = 0x9c.toByte()
        packet[21] = 0x40
        packet[22] = 0
        packet[23] = 53
        assertTrue(http2PacketLane(packet, 4) == 0)

        packet[22] = 1
        packet[23] = 187.toByte()
        val lane = http2PacketLane(packet, 4)
        assertTrue(lane in 1..3)
        packet[4] = 0x12
        packet[5] = 0x34
        packet[10] = 0x56
        packet[11] = 0x78
        assertTrue(http2PacketLane(packet, 4) == lane)
    }

    @Test
    fun extractsOnlyValidGatewayHostname() {
        assertTrue(gatewayHost("https://vpn.example.com:8443") == "vpn.example.com")
        assertTrue(gatewayHost("https://[2001:db8::1]:8443") == "2001:db8::1")
        assertTrue(gatewayHost("not a URL") == null)
    }

    @Test
    fun acceptsOnlyAssignedIPv4Source() {
        val assigned = parseIPv4Address("10.66.0.2")!!
        val packet = ByteArray(20)
        packet[0] = 0x45
        packet[3] = packet.size.toByte()
        packet[12] = 10
        packet[13] = 66
        packet[14] = 0
        packet[15] = 2

        assertTrue(isAssignedIPv4Packet(packet, packet.size, assigned))

        packet[15] = 3
        assertFalse(isAssignedIPv4Packet(packet, packet.size, assigned))

        packet[0] = 0x60
        assertFalse(isAssignedIPv4Packet(packet, packet.size, assigned))
        assertFalse(isAssignedIPv4Packet(packet, 19, assigned))
    }

    @Test
    fun keepsEveryFragmentOfADatagramOnTheSameLane() {
        val packet = ByteArray(28)
        packet[0] = 0x45
        packet[3] = packet.size.toByte()
        packet[4] = 0x12
        packet[5] = 0x34
        packet[6] = 0x20
        packet[9] = 17
        packet[12] = 10
        packet[15] = 2
        packet[16] = 1
        packet[19] = 1
        packet[23] = 53
        val firstLane = http2PacketLane(packet, 4)
        assertTrue(firstLane in 1..3)

        packet[6] = 0
        for (offset in 1..255) {
            packet[7] = offset.toByte()
            packet[20] = offset.toByte()
            packet[23] = (255 - offset).toByte()
            assertEquals(firstLane, http2PacketLane(packet, 4))
        }
        packet[4] = 0x56
        packet[5] = 0x78
        assertEquals(firstLane, http2PacketLane(packet, 4))
    }

    @Test
    fun rejectsInvalidIPv4LengthsWithoutReadingOutsideBuffer() {
        val source = parseIPv4Address("10.66.0.2")!!
        val packet = ByteArray(20)
        packet[0] = 0x45
        packet[3] = 20
        source.copyInto(packet, 12)
        assertTrue(isAssignedIPv4Packet(packet, 20, source))
        assertFalse(isAssignedIPv4Packet(ByteArray(0), 20, source))
        assertFalse(isAssignedIPv4Packet(packet, 21, source))
        packet[0] = 0x44
        assertFalse(isAssignedIPv4Packet(packet, 20, source))
        packet[0] = 0x46
        assertFalse(isAssignedIPv4Packet(packet, 20, source))
        packet[0] = 0x45
        packet[3] = 19
        assertFalse(isAssignedIPv4Packet(packet, 20, source))
    }

    @Test
    fun validatesGatewayPortsAndHttpHeaderTokensBeforeStartingService() {
        for (server in listOf("https://vpn.example.com", "https://[::1]:8443/")) {
            assertTrue(server, isHttpsOrigin(server))
        }
        for (server in listOf(
            "https://vpn.example.com:0", "https://vpn.example.com:65536",
            "https://vpn.example.com/path", "http://vpn.example.com", "https://user@vpn.example.com",
        )) {
            assertFalse(server, isHttpsOrigin(server))
        }
        assertTrue(isValidToken("token-123"))
        assertFalse(isValidToken("token\r\nInjected: header"))
        assertFalse(isValidToken("token\u007f"))
        assertFalse(isValidToken("   "))
    }

    @Test
    fun rejectsNonCanonicalLeaseAddresses() {
        for (address in listOf("+10.66.0.2", "010.66.0.2", "10.66.0.256", "10.66.0", "10..0.2")) {
            assertNull(address, parseIPv4Address(address))
        }
    }
}
