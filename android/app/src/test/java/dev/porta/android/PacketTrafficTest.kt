package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketTrafficTest {
    @Test
    fun reservesLaneZeroForDnsIcmpAckOnlyAndSmallUdp() {
        val dns = udpPacket(sourcePort = 40_000, destinationPort = 53, payloadBytes = 300)
        val icmp = ipv4Packet(protocol = 1, transportBytes = 8)
        val ack = tcpPacket(sourcePort = 443, destinationPort = 40_000, flags = 0x10)
        val smallUdp = udpPacket(sourcePort = 123, destinationPort = 40_000, payloadBytes = 32)

        for (packet in listOf(dns, icmp, ack, smallUdp)) {
            assertEquals(PacketClass.CONTROL, classifyIPv4Packet(packet).packetClass)
            assertEquals(0, http2PacketLane(packet, 4))
        }
    }

    @Test
    fun tcpAckWithPayloadOrLifecycleFlagsUsesDataLane() {
        val ackWithPayload = tcpPacket(
            sourcePort = 443,
            destinationPort = 40_000,
            flags = 0x10,
            payloadBytes = 1,
        )
        val synAck = tcpPacket(
            sourcePort = 443,
            destinationPort = 40_000,
            flags = 0x12,
        )

        for (packet in listOf(ackWithPayload, synAck)) {
            assertEquals(PacketClass.TCP, classifyIPv4Packet(packet).packetClass)
            assertTrue(http2PacketLane(packet, 4) in 1..3)
        }
    }

    @Test
    fun fragmentsAreNeverClassifiedAsSmallUdpControlAndStayTogether() {
        val first = udpPacket(
            sourcePort = 40_000,
            destinationPort = 53,
            payloadBytes = 16,
            fragmentId = 0x1234,
            flagsAndOffset = 0x2000,
        )
        val continuation = first.copyOf().also {
            it[6] = 0
            it[7] = 1
            repeat(8) { index -> it[20 + index] = (index * 13).toByte() }
        }

        assertEquals(PacketClass.DATAGRAM, classifyIPv4Packet(first).packetClass)
        assertEquals(PacketClass.DATAGRAM, classifyIPv4Packet(continuation).packetClass)
        assertEquals(http2PacketLane(first, 4), http2PacketLane(continuation, 4))

        val otherDatagram = continuation.copyOf().also {
            it[4] = 0x56
            it[5] = 0x78
        }
        assertNotEquals(
            classifyIPv4Packet(first).flow,
            classifyIPv4Packet(otherDatagram).flow,
        )
    }

    @Test
    fun ordinaryFlowRoutingIgnoresPacketIdsChecksumsAndPayload() {
        val packet = tcpPacket(
            sourcePort = 40_000,
            destinationPort = 443,
            flags = 0x18,
            payloadBytes = 64,
        )
        val lane = http2PacketLane(packet, 4)

        repeat(32) { value ->
            val changed = packet.copyOf()
            changed[4] = value.toByte()
            changed[5] = (255 - value).toByte()
            changed[10] = (value * 3).toByte()
            changed[11] = (value * 7).toByte()
            changed[changed.lastIndex] = value.toByte()
            assertEquals(lane, http2PacketLane(changed, 4))
        }
    }
}

internal fun tcpPacket(
    sourcePort: Int,
    destinationPort: Int,
    flags: Int = 0x18,
    payloadBytes: Int = 0,
): ByteArray {
    val packet = ipv4Packet(protocol = 6, transportBytes = 20 + payloadBytes)
    writeShort(packet, 20, sourcePort)
    writeShort(packet, 22, destinationPort)
    packet[32] = 0x50
    packet[33] = flags.toByte()
    return packet
}

internal fun udpPacket(
    sourcePort: Int,
    destinationPort: Int,
    payloadBytes: Int,
    fragmentId: Int = 0,
    flagsAndOffset: Int = 0,
): ByteArray {
    val packet = ipv4Packet(
        protocol = 17,
        transportBytes = 8 + payloadBytes,
        fragmentId = fragmentId,
        flagsAndOffset = flagsAndOffset,
    )
    writeShort(packet, 20, sourcePort)
    writeShort(packet, 22, destinationPort)
    writeShort(packet, 24, 8 + payloadBytes)
    return packet
}

private fun ipv4Packet(
    protocol: Int,
    transportBytes: Int,
    fragmentId: Int = 0,
    flagsAndOffset: Int = 0,
): ByteArray {
    val packet = ByteArray(20 + transportBytes)
    packet[0] = 0x45
    writeShort(packet, 2, packet.size)
    writeShort(packet, 4, fragmentId)
    writeShort(packet, 6, flagsAndOffset)
    packet[8] = 64
    packet[9] = protocol.toByte()
    packet[12] = 10
    packet[13] = 66
    packet[15] = 2
    packet[16] = 1
    packet[17] = 1
    packet[18] = 1
    packet[19] = 1
    return packet
}

private fun writeShort(packet: ByteArray, offset: Int, value: Int) {
    packet[offset] = (value ushr 8).toByte()
    packet[offset + 1] = value.toByte()
}
