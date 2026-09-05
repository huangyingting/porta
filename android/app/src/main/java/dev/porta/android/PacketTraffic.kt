package dev.porta.android

internal enum class PacketClass {
    TCP,
    DATAGRAM,
    CONTROL,
}

internal data class PacketFlowKey(
    val sourceAddress: Int,
    val destinationAddress: Int,
    val sourcePort: Int,
    val destinationPort: Int,
    val fragmentId: Int,
    val protocol: Int,
    val fragmented: Boolean,
)

internal data class PacketMetadata(
    val packetClass: PacketClass,
    val flow: PacketFlowKey,
    val hash: Int,
)

internal fun classifyIPv4Packet(packet: ByteArray, length: Int = packet.size): PacketMetadata {
    var packetClass = PacketClass.DATAGRAM
    var sourceAddress = 0
    var destinationAddress = 0
    var sourcePort = 0
    var destinationPort = 0
    var fragmentId = 0
    var protocol = 0
    var fragmented = false
    var headerLength = 0

    if (length in 20..packet.size && (packet[0].toInt() ushr 4) == 4) {
        headerLength = (packet[0].toInt() and 0x0f) * 4
        if (headerLength in 20..length) {
            sourceAddress = readInt(packet, 12)
            destinationAddress = readInt(packet, 16)
            protocol = packet[9].toInt() and 0xff
            val flagsAndOffset = readUnsignedShort(packet, 6)
            fragmented = flagsAndOffset and 0x3fff != 0
            if (fragmented) fragmentId = readUnsignedShort(packet, 4)
            val hasPorts = !fragmented && (protocol == 6 || protocol == 17) &&
                length >= headerLength + 4
            if (hasPorts) {
                sourcePort = readUnsignedShort(packet, headerLength)
                destinationPort = readUnsignedShort(packet, headerLength + 2)
            }
            packetClass = when (protocol) {
                1 -> PacketClass.CONTROL
                6 -> when {
                    hasPorts && (sourcePort == 53 || destinationPort == 53) ->
                        PacketClass.CONTROL
                    hasPorts && isTcpAckOnly(packet, length, headerLength) ->
                        PacketClass.CONTROL
                    else -> PacketClass.TCP
                }
                17 -> when {
                    hasPorts && (sourcePort == 53 || destinationPort == 53) ->
                        PacketClass.CONTROL
                    hasPorts && length <= SMALL_UDP_CONTROL_MAX_BYTES ->
                        PacketClass.CONTROL
                    else -> PacketClass.DATAGRAM
                }
                else -> PacketClass.DATAGRAM
            }
        }
    }

    val flow = PacketFlowKey(
        sourceAddress = sourceAddress,
        destinationAddress = destinationAddress,
        sourcePort = sourcePort,
        destinationPort = destinationPort,
        fragmentId = fragmentId,
        protocol = protocol,
        fragmented = fragmented,
    )
    return PacketMetadata(packetClass, flow, hashFlow(flow))
}

internal fun http2PacketLane(packet: ByteArray, laneCount: Int): Int {
    if (laneCount <= 1) return 0
    val metadata = classifyIPv4Packet(packet)
    if (metadata.packetClass == PacketClass.CONTROL) return 0
    return 1 + (Integer.toUnsignedLong(metadata.hash) % (laneCount - 1).toLong()).toInt()
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

private fun hashFlow(flow: PacketFlowKey): Int {
    var hash = FNV_OFFSET_BASIS
    fun add(value: Int) {
        hash = hash xor (value and 0xff)
        hash *= FNV_PRIME
    }
    for (shift in 24 downTo 0 step 8) add(flow.sourceAddress ushr shift)
    for (shift in 24 downTo 0 step 8) add(flow.destinationAddress ushr shift)
    add(flow.sourcePort ushr 8)
    add(flow.sourcePort)
    add(flow.destinationPort ushr 8)
    add(flow.destinationPort)
    add(flow.fragmentId ushr 8)
    add(flow.fragmentId)
    add(flow.protocol)
    add(if (flow.fragmented) 1 else 0)
    return hash
}

private fun readUnsignedShort(packet: ByteArray, offset: Int): Int =
    ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

private fun readInt(packet: ByteArray, offset: Int): Int =
    ((packet[offset].toInt() and 0xff) shl 24) or
        ((packet[offset + 1].toInt() and 0xff) shl 16) or
        ((packet[offset + 2].toInt() and 0xff) shl 8) or
        (packet[offset + 3].toInt() and 0xff)

private const val SMALL_UDP_CONTROL_MAX_BYTES = 256
private const val TCP_FIN = 0x01
private const val TCP_SYN = 0x02
private const val TCP_RST = 0x04
private const val TCP_ACK = 0x10
private const val FNV_OFFSET_BASIS = -2128831035
private const val FNV_PRIME = 16777619
