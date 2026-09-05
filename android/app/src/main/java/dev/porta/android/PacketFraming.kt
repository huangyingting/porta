package dev.porta.android

import okio.BufferedSink
import okio.BufferedSource
import java.io.EOFException

object PacketFraming {
    const val CONTENT_TYPE = "application/x-porta-packets"
    const val VERSION = "2"
    const val MAX_PACKET = 65_535

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

    internal fun writePacketBatch(sink: BufferedSink, packets: List<PacketBuffer>): Long {
        require(packets.all { it.length <= MAX_PACKET }) { "packet is too large" }
        var bytes = 0L
        for (packet in packets) {
            sink.writeShort(packet.length)
            if (packet.length > 0) sink.write(packet.bytes, 0, packet.length)
            bytes += packet.length
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

    @Throws(EOFException::class)
    fun readInto(source: BufferedSource, destination: ByteArray): Int? {
        val size = source.readShort().toInt() and 0xffff
        if (size == 0) return null
        require(size <= destination.size) { "packet buffer is too small" }
        var offset = 0
        while (offset < size) {
            val read = source.read(destination, offset, size - offset)
            if (read < 0) throw EOFException()
            offset += read
        }
        return size
    }
}
