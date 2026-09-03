package dev.htun.android

import okio.BufferedSink
import okio.BufferedSource
import java.io.EOFException

object PacketFraming {
    const val CONTENT_TYPE = "application/x-htun-packets"
    const val VERSION = "1"
    private const val MAX_PACKET = 65_535

    fun write(sink: BufferedSink, packet: ByteArray) {
        require(packet.size <= MAX_PACKET) { "packet is too large" }
        sink.writeShort(packet.size)
        if (packet.isNotEmpty()) sink.write(packet)
        sink.flush()
    }

    @Throws(EOFException::class)
    fun read(source: BufferedSource): ByteArray? {
        val size = source.readShort().toInt() and 0xffff
        if (size == 0) return null
        return source.readByteArray(size.toLong())
    }
}

