package dev.htun.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketFilterTest {
    @Test
    fun migratesPreviousDefaultGatewayToDirectMasqueEndpoint() {
        assertTrue(preferredGateway("https://htun.i-csu.org") == "https://htun.i-csu.org:8443")
        assertTrue(preferredGateway("https://vpn.example.com") == "https://vpn.example.com")
    }

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
    fun extractsOnlyValidGatewayHostname() {
        assertTrue(gatewayHost("https://htun.i-csu.org:8443") == "htun.i-csu.org")
        assertTrue(gatewayHost("https://[2001:db8::1]:8443") == "2001:db8::1")
        assertTrue(gatewayHost("not a URL") == null)
    }

    @Test
    fun acceptsOnlyAssignedIPv4Source() {
        val assigned = parseIPv4Address("10.66.0.2")!!
        val packet = ByteArray(20)
        packet[0] = 0x45
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
}
