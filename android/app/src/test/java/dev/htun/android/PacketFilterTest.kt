package dev.htun.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketFilterTest {
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
