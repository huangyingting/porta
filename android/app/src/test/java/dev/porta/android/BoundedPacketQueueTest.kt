package dev.porta.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedPacketQueueTest {
    @Test
    fun tailDropsNewTcpAndPreservesQueuedPrefix() {
        val queue = queue(maxPackets = 2, maxBytes = 20)
        assertTrue(queue.offer(packet(1, 8), PacketClass.TCP, 0))
        assertTrue(queue.offer(packet(2, 8), PacketClass.TCP, 1))
        val rejected = packet(3, 8)

        assertFalse(queue.offer(rejected, PacketClass.TCP, 2))
        rejected.release()

        assertPacket(1, queue.pollNow(2))
        assertPacket(2, queue.pollNow(2))
        val snapshot = queue.snapshot(2)
        assertEquals(1L, snapshot.tailDrops)
        assertEquals(1L, snapshot.droppedByClass[PacketClass.TCP])
    }

    @Test
    fun controlDropsOldestDatagramWithoutEvictingTcp() {
        val queue = queue(maxPackets = 3, maxBytes = 30)
        assertTrue(queue.offer(packet(1, 8), PacketClass.TCP, 0))
        assertTrue(queue.offer(packet(2, 8), PacketClass.DATAGRAM, 1))
        assertTrue(queue.offer(packet(3, 8), PacketClass.CONTROL, 2))
        assertTrue(queue.offer(packet(4, 8), PacketClass.CONTROL, 3))

        assertPacket(1, queue.pollNow(3))
        assertPacket(3, queue.pollNow(3))
        assertPacket(4, queue.pollNow(3))
        assertEquals(1, queue.snapshot(3).oldestDrops)
    }

    @Test
    fun tcpDropsOldestDatagramBeforeTailDropping() {
        val queue = queue(maxPackets = 1, maxBytes = 20)
        assertTrue(queue.offer(packet(1, 8), PacketClass.DATAGRAM, 0))

        assertTrue(queue.offer(packet(2, 8), PacketClass.TCP, 1))

        assertPacket(2, queue.pollNow(1))
        val snapshot = queue.snapshot(1)
        assertEquals(1L, snapshot.oldestDrops)
        assertEquals(0L, snapshot.tailDrops)
    }

    @Test
    fun drainBatchRespectsPacketAndByteLimits() {
        val queue = queue(maxPackets = 4, maxBytes = 40)
        repeat(3) { assertTrue(queue.offer(packet(it, 8), PacketClass.TCP)) }
        val destination = mutableListOf(packet(9, 8))

        assertEquals(1, queue.drainTo(destination, maximum = 3, maximumBytes = 20))
        assertEquals(2, destination.size)
        assertEquals(2, queue.snapshot().packets)
        destination.forEach(PacketBuffer::release)
        queue.clear()
    }

    @Test
    fun queueTransferCanPreserveOriginalPacketAge() {
        var now = 0L
        val config = PacketQueueConfig(
            maxPackets = 2,
            maxBytes = 20,
            tcpMaxAgeMillis = 100,
            datagramMaxAgeMillis = 100,
            controlMaxAgeMillis = 100,
        )
        val source = BoundedPacketQueue(config, clockNanos = { now })
        val destination = BoundedPacketQueue(config, clockNanos = { now })
        assertTrue(source.offer(packet(1, 8), PacketClass.TCP))
        now = TimeUnit.MILLISECONDS.toNanos(90)
        val queued = source.pollEntryNow()!!
        assertTrue(
            destination.offer(
                queued.packet,
                PacketClass.TCP,
                enqueuedNanos = queued.enqueuedNanos,
            ),
        )

        now = TimeUnit.MILLISECONDS.toNanos(100)

        assertEquals(0, destination.snapshot().packets)
        assertEquals(1L, destination.snapshot().expiredDrops)
    }

    @Test
    fun expiresPacketsByClassAndReportsHighWaterAndAge() {
        var now = 0L
        val queue = BoundedPacketQueue(
            PacketQueueConfig(
                maxPackets = 4,
                maxBytes = 40,
                tcpMaxAgeMillis = 100,
                datagramMaxAgeMillis = 10,
                controlMaxAgeMillis = 20,
            ),
            clockNanos = { now },
        )
        queue.offer(packet(1, 8), PacketClass.TCP)
        queue.offer(packet(2, 8), PacketClass.DATAGRAM)
        now = TimeUnit.MILLISECONDS.toNanos(15)

        val snapshot = queue.snapshot()

        assertEquals(1, snapshot.packets)
        assertEquals(8, snapshot.bytes)
        assertEquals(2, snapshot.highWaterPackets)
        assertEquals(16, snapshot.highWaterBytes)
        assertEquals(15, snapshot.oldestAgeMillis)
        assertEquals(1L, snapshot.expiredDrops)
        assertEquals(1L, snapshot.droppedByClass[PacketClass.DATAGRAM])
    }

    @Test
    fun concurrentOffersNeverExceedAtomicBounds() {
        val queue = queue(maxPackets = 8, maxBytes = 64)
        val start = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(8)
        repeat(64) { value ->
            workers.execute {
                start.await()
                val packet = packet(value, 8)
                if (!queue.offer(packet, PacketClass.TCP, 0)) packet.release()
            }
        }
        start.countDown()
        workers.shutdown()
        assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS))

        val snapshot = queue.snapshot(0)
        assertEquals(8, snapshot.packets)
        assertEquals(64, snapshot.bytes)
        assertEquals(56, snapshot.tailDrops)
    }

    @Test
    fun pooledBuffersReturnOnlyAfterQueueOwnershipEnds() {
        val pool = PacketBufferPool(bufferSize = 16, maxCachedBuffers = 1)
        val bytes = pool.acquire()
        val packet = PacketBuffer.pooled(bytes, 4, pool)
        val queue = queue(maxPackets = 1, maxBytes = 16)
        assertTrue(queue.offer(packet, PacketClass.DATAGRAM, 0))
        assertEquals(0, pool.cachedBuffers())

        queue.clear()

        assertEquals(1, pool.cachedBuffers())
    }

    private fun queue(maxPackets: Int, maxBytes: Int) = BoundedPacketQueue(
        PacketQueueConfig(
            maxPackets = maxPackets,
            maxBytes = maxBytes,
            tcpMaxAgeMillis = 1_000,
            datagramMaxAgeMillis = 1_000,
            controlMaxAgeMillis = 1_000,
        ),
    )

    private fun packet(value: Int, size: Int): PacketBuffer =
        PacketBuffer.wrap(ByteArray(size) { value.toByte() })

    private fun assertPacket(value: Int, packet: PacketBuffer?) {
        requireNotNull(packet)
        assertArrayEquals(ByteArray(packet.length) { value.toByte() }, packet.copyBytes())
        packet.release()
    }
}
