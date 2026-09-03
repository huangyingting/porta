package dev.porta.android

import okio.Buffer
import org.junit.Assert.assertArrayEquals
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
}

