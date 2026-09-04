package dev.porta.android

import okio.BufferedSink
import okio.BufferedSource
import java.io.EOFException

object PacketFraming {
    const val CONTENT_TYPE = "application/x-porta-packets"
    const val VERSION = "2"
    private const val MAX_PACKET = 65_535

    fun write(sink: BufferedSink, packet: ByteArray) {
        require(packet.size <= MAX_PACKET) { "packet is too large" }
        writeFrame(sink, packet)
        sink.flush()
    }

    internal fun writeBatch(sink: BufferedSink, packets: List<ByteArray>): Long {
        require(packets.all { it.size <= MAX_PACKET }) { "packet is too large" }
        var bytes = 0L
        for (packet in packets) {
            writeFrame(sink, packet)
            bytes += packet.size
        }
        if (packets.isNotEmpty()) sink.flush()
        return bytes
    }

    private fun writeFrame(sink: BufferedSink, packet: ByteArray) {
        sink.writeShort(packet.size)
        if (packet.isNotEmpty()) sink.write(packet)
    }

    @Throws(EOFException::class)
    fun read(source: BufferedSource): ByteArray? {
        val size = source.readShort().toInt() and 0xffff
        if (size == 0) return null
        return source.readByteArray(size.toLong())
    }
}
