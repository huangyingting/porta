package dev.porta.android

internal enum class PacketClass {
    TCP,
    DATAGRAM,
    CONTROL,
}

internal fun classifyIPv4Packet(packet: ByteArray, length: Int = packet.size): PacketClass {
    if (length !in 20..packet.size || (packet[0].toInt() ushr 4) != 4) {
        return PacketClass.DATAGRAM
    }
    val headerLength = (packet[0].toInt() and 0x0f) * 4
    if (headerLength !in 20..length) {
        return PacketClass.DATAGRAM
    }
    val protocol = packet[9].toInt() and 0xff
    val flagsAndOffset = readUnsignedShort(packet, 6)
    val fragmented = flagsAndOffset and 0x3fff != 0
    var sourcePort = 0
    var destinationPort = 0
    val hasPorts = !fragmented && (protocol == 6 || protocol == 17) &&
        length >= headerLength + 4
    if (hasPorts) {
        sourcePort = readUnsignedShort(packet, headerLength)
        destinationPort = readUnsignedShort(packet, headerLength + 2)
    }
    return when (protocol) {
        1 -> PacketClass.CONTROL
        6 -> when {
            hasPorts && (sourcePort == 53 || destinationPort == 53) -> PacketClass.CONTROL
            hasPorts && isTcpAckOnly(packet, length, headerLength) -> PacketClass.CONTROL
            else -> PacketClass.TCP
        }
        17 -> when {
            hasPorts && (sourcePort == 53 || destinationPort == 53) -> PacketClass.CONTROL
            hasPorts && length <= SMALL_UDP_CONTROL_MAX_BYTES -> PacketClass.CONTROL
            else -> PacketClass.DATAGRAM
        }
        else -> PacketClass.DATAGRAM
    }
}

private fun isTcpAckOnly(packet: ByteArray, length: Int, ipHeaderLength: Int): Boolean {
    if (length < ipHeaderLength + 20) return false
    val tcpHeaderLength = ((packet[ipHeaderLength + 12].toInt() and 0xff) ushr 4) * 4
    if (tcpHeaderLength < 20 || length < ipHeaderLength + tcpHeaderLength) return false
    val flags = packet[ipHeaderLength + 13].toInt() and 0xff
    val disallowed = TCP_FIN or TCP_SYN or TCP_RST
    return flags and TCP_ACK != 0 &&
        flags and disallowed == 0 &&
        length == ipHeaderLength + tcpHeaderLength
}

private fun readUnsignedShort(packet: ByteArray, offset: Int): Int =
    ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

private const val SMALL_UDP_CONTROL_MAX_BYTES = 256
private const val TCP_FIN = 0x01
private const val TCP_SYN = 0x02
private const val TCP_RST = 0x04
private const val TCP_ACK = 0x10
