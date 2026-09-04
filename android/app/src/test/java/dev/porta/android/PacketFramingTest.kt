package dev.porta.android

import okio.Buffer
import okio.ForwardingSink
import okio.buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PacketFramingTest {
    @Test
    fun roundTripsPacketAndKeepalive() {
        val stream = Buffer()
        PacketFraming.write(stream, byteArrayOf(1, 2, 3))
        PacketFraming.write(stream, byteArrayOf())

        assertArrayEquals(byteArrayOf(1, 2, 3), PacketFraming.read(stream))
        assertNull(PacketFraming.read(stream))
    }

    @Test
    fun batchesFramesWithoutChangingWireFormatOrFlushingEveryPacket() {
        val stream = Buffer()
        var flushes = 0
        val sink = object : ForwardingSink(stream) {
            override fun flush() {
                flushes++
                super.flush()
            }
        }.buffer()
        val packets = List(16) { ByteArray(1100) { it.toByte() } }

        assertEquals(17_600L, PacketFraming.writeBatch(sink, packets))
        assertEquals(1, flushes)
        packets.forEach { assertArrayEquals(it, PacketFraming.read(stream)) }
        assertEquals(0L, stream.size)
        assertEquals(0L, PacketFraming.writeBatch(sink, emptyList()))
        assertEquals(1, flushes)
    }

    @Test(expected = java.io.EOFException::class)
    fun rejectsTruncatedFrame() {
        val stream = Buffer().writeShort(3).write(byteArrayOf(1, 2))
        PacketFraming.read(stream)
    }

    @Test
    fun rejectsOversizedBatchBeforeWritingPartialFrames() {
        val stream = Buffer()
        try {
            PacketFraming.writeBatch(stream, listOf(byteArrayOf(1), ByteArray(65_536)))
            org.junit.Assert.fail("Expected an oversized packet error")
        } catch (_: IllegalArgumentException) {
            assertEquals(0L, stream.size)
        }
    }
}
