package dev.porta.android

import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Http2SchedulingTest {
    @Test
    fun laneZeroGetsPriorityWithoutStarvingDataLanes() {
        val signal = PacketQueueSignal()
        val queues = List(4) { BoundedPacketQueue(queueConfig(), signal) }
        val scheduler = FairLanePacketScheduler(queues, signal, laneZeroBurst = 3)
        repeat(6) { queues[0].offer(packet(it), PacketClass.CONTROL) }
        queues[1].offer(packet(10), PacketClass.TCP)
        queues[2].offer(packet(20), PacketClass.TCP)

        val lanes = List(8) {
            scheduler.pollNow()!!.also { it.packet.release() }.lane
        }

        assertEquals(listOf(0, 0, 0, 1, 0, 0, 0, 2), lanes)
        assertNull(scheduler.pollNow())
    }

    @Test
    fun preservesFifoWithinEveryLane() {
        val signal = PacketQueueSignal()
        val queues = List(3) { BoundedPacketQueue(queueConfig(), signal) }
        val scheduler = FairLanePacketScheduler(queues, signal, laneZeroBurst = 1)
        listOf(1, 2, 3).forEach { queues[1].offer(packet(it), PacketClass.TCP) }
        listOf(4, 5).forEach { queues[2].offer(packet(it), PacketClass.TCP) }

        val byLane = mutableMapOf<Int, MutableList<Int>>()
        repeat(5) {
            val scheduled = scheduler.poll(1, TimeUnit.SECONDS)!!
            byLane.getOrPut(scheduled.lane, ::mutableListOf).add(
                scheduled.packet.bytes[0].toInt(),
            )
            scheduled.packet.release()
        }

        assertEquals(listOf(1, 2, 3), byLane[1])
        assertEquals(listOf(4, 5), byLane[2])
    }

    @Test
    fun stableRouterPinsFlowsAndRoutesAroundUnavailableLanes() {
        val ready = mutableSetOf(1, 2)
        val queued = intArrayOf(0, 0, 100, 0)
        val router = StableDataLaneRouter(
            laneCount = 4,
            isLaneReady = ready::contains,
            queuedBytes = { queued[it] },
        )
        val metadata = classifyIPv4Packet(
            tcpPacket(sourcePort = 40_000, destinationPort = 443, payloadBytes = 1),
        )

        val first = router.select(metadata)!!
        assertEquals(1, first)
        ready += 3
        queued[first] = 10_000
        queued[3] = 0
        assertEquals(first, router.select(metadata))

        ready -= first
        val replacement = router.select(metadata)
        assertTrue(replacement in ready)
    }

    @Test
    fun expiredFlowIsReassignedToTheCurrentLeastLoadedHealthyLane() {
        var now = 0L
        val queued = intArrayOf(0, 0, 100)
        val router = StableDataLaneRouter(
            laneCount = 3,
            isLaneReady = { it in 1..2 },
            queuedBytes = { queued[it] },
            clockNanos = { now },
            flowIdleNanos = 100,
            pruneIntervalNanos = 1_000,
        )
        val flow = classifyIPv4Packet(
            tcpPacket(sourcePort = 40_000, destinationPort = 443, payloadBytes = 1),
        )
        assertEquals(1, router.select(flow))
        queued[1] = 100
        queued[2] = 0

        now = 100

        assertEquals(2, router.select(flow))
    }

    @Test
    fun fragmentedDatagramRemainsPinnedWhenQueueDepthsChange() {
        val queued = intArrayOf(0, 0, 100)
        val router = StableDataLaneRouter(
            laneCount = 3,
            isLaneReady = { it in 1..2 },
            queuedBytes = { queued[it] },
        )
        val first = classifyIPv4Packet(fragmentPacket(fragmentId = 0x1234, offset = 0))
        val continuation = classifyIPv4Packet(fragmentPacket(fragmentId = 0x1234, offset = 7))
        val lane = router.select(first)!!
        queued[lane] = 1_000
        queued[if (lane == 1) 2 else 1] = 0

        assertEquals(first.flow, continuation.flow)
        assertEquals(lane, router.select(continuation))
    }

    @Test
    fun flowAssignmentTableStaysBounded() {
        val router = StableDataLaneRouter(
            laneCount = 3,
            isLaneReady = { it in 1..2 },
            queuedBytes = { 0 },
            maxFlowAssignments = 3,
        )

        repeat(10) { index ->
            router.select(
                classifyIPv4Packet(
                    tcpPacket(
                        sourcePort = 40_000 + index,
                        destinationPort = 443,
                        payloadBytes = 1,
                    ),
                ),
            )
        }

        assertEquals(3, router.assignmentCount())
    }

    @Test
    fun idleCleanupRemovesUnrelatedExpiredAssignments() {
        var now = 0L
        val router = StableDataLaneRouter(
            laneCount = 3,
            isLaneReady = { it in 1..2 },
            queuedBytes = { 0 },
            clockNanos = { now },
            flowIdleNanos = 100,
            pruneIntervalNanos = 0,
        )
        repeat(3) { index ->
            router.select(
                classifyIPv4Packet(
                    tcpPacket(
                        sourcePort = 40_000 + index,
                        destinationPort = 443,
                        payloadBytes = 1,
                    ),
                ),
            )
        }
        assertEquals(3, router.assignmentCount())

        now = 100
        router.select(
            classifyIPv4Packet(
                tcpPacket(sourcePort = 50_000, destinationPort = 443, payloadBytes = 1),
            ),
        )

        assertEquals(1, router.assignmentCount())
    }

    @Test
    fun adaptiveControllerStartsWithTwoAndScalesOnlyOnSustainedSignals() {
        val controller = AdaptiveLaneController(
            laneCount = 4,
            blockedWritesRequired = 3,
            scaleCooldownMillis = 1_000,
        )
        assertEquals(setOf(0, 1), controller.desiredLanes())
        assertNull(controller.observePressure(0.5, 0))
        assertEquals(2, controller.observePressure(0.8, 0))
        assertNull(controller.observePressure(0.8, 500))
        assertNull(controller.observeBlockedWrite(100, 1_000))
        assertNull(controller.observeBlockedWrite(100, 1_001))
        assertEquals(3, controller.observeBlockedWrite(100, 1_002))
        assertEquals(setOf(0, 1, 2, 3), controller.desiredLanes())
    }

    @Test
    fun laneFailureActivatesStandbyWithoutWaitingForPressureCooldown() {
        val controller = AdaptiveLaneController(laneCount = 4, scaleCooldownMillis = 10_000)
        assertEquals(2, controller.observePressure(1.0, 0))
        assertEquals(3, controller.observeLaneFailure(1))
        assertEquals(setOf(0, 1, 2, 3), controller.desiredLanes())
    }

    @Test
    fun dispatcherQueuesDataUntilAHealthyLaneCanAcceptNewFlows() {
        val ready = mutableSetOf<Int>()
        val queues = List(4) { BoundedPacketQueue(queueConfig()) }
        val pending = BoundedPacketQueue(queueConfig())
        val dispatcher = Http2PacketDispatcher(
            laneQueues = queues,
            pendingQueue = pending,
            isLaneReady = ready::contains,
            adaptiveLanes = AdaptiveLaneController(),
            requestLaneActivation = {},
        )
        val data = PacketBuffer.wrap(
            tcpPacket(sourcePort = 40_000, destinationPort = 443, payloadBytes = 1),
        )
        assertTrue(dispatcher.offer(data))
        assertEquals(1, pending.snapshot().packets)
        assertEquals(0, queues.sumOf { it.snapshot().packets })

        ready += 1
        dispatcher.laneBecameReady()

        assertEquals(0, pending.snapshot().packets)
        assertEquals(1, queues[1].snapshot().packets)
        queues.forEach(BoundedPacketQueue::clear)
    }

    @Test
    fun dispatcherDoesNotSpinWhenOnlyControlLaneBecomesReady() {
        val ready = mutableSetOf(0)
        val queues = List(4) { BoundedPacketQueue(queueConfig()) }
        val pending = BoundedPacketQueue(queueConfig())
        val dispatcher = Http2PacketDispatcher(
            laneQueues = queues,
            pendingQueue = pending,
            isLaneReady = ready::contains,
            adaptiveLanes = AdaptiveLaneController(),
            requestLaneActivation = {},
        )
        assertTrue(
            dispatcher.offer(
                PacketBuffer.wrap(
                    tcpPacket(sourcePort = 40_000, destinationPort = 443, payloadBytes = 1),
                ),
            ),
        )

        dispatcher.laneBecameReady()

        assertEquals(1, pending.snapshot().packets)
        assertEquals(0, queues.sumOf { it.snapshot().packets })
        pending.clear()
    }

    @Test
    fun dispatcherDiscardsQueuedPacketsWhenDataLaneFails() {
        val ready = mutableSetOf(1, 2)
        val queues = List(4) { BoundedPacketQueue(queueConfig()) }
        val pending = BoundedPacketQueue(queueConfig())
        val dispatcher = Http2PacketDispatcher(
            laneQueues = queues,
            pendingQueue = pending,
            isLaneReady = ready::contains,
            adaptiveLanes = AdaptiveLaneController(),
            requestLaneActivation = {},
        )
        val packet = PacketBuffer.wrap(
            tcpPacket(sourcePort = 40_000, destinationPort = 443, payloadBytes = 1),
        )
        assertTrue(dispatcher.offer(packet))
        val failedLane = (1..2).single { queues[it].snapshot().packets == 1 }
        ready.remove(failedLane)

        dispatcher.laneBecameUnavailable(queues[failedLane])

        assertEquals(0, queues[failedLane].snapshot().packets)
        assertEquals(1, queues[failedLane].snapshot().recoveryDrops)
        assertEquals(0, queues[if (failedLane == 1) 2 else 1].snapshot().packets)
        queues.forEach(BoundedPacketQueue::clear)
    }

    @Test
    fun dispatcherRoutesControlToHealthyDataLaneWhileLaneZeroRecovers() {
        val ready = mutableSetOf(1)
        val queues = List(4) { BoundedPacketQueue(queueConfig()) }
        val pending = BoundedPacketQueue(queueConfig())
        val dispatcher = Http2PacketDispatcher(
            laneQueues = queues,
            pendingQueue = pending,
            isLaneReady = ready::contains,
            adaptiveLanes = AdaptiveLaneController(),
            requestLaneActivation = {},
        )
        val control = PacketBuffer.wrap(
            udpPacket(sourcePort = 40_000, destinationPort = 53, payloadBytes = 8),
        )

        assertTrue(dispatcher.offer(control))

        assertEquals(0, queues[0].snapshot().packets)
        assertEquals(1, queues[1].snapshot().packets)
        queues.forEach(BoundedPacketQueue::clear)
    }

    private fun packet(value: Int) = PacketBuffer.wrap(byteArrayOf(value.toByte()))

    private fun queueConfig() = PacketQueueConfig(
        maxPackets = 32,
        maxBytes = 4_096,
        tcpMaxAgeMillis = 1_000,
        datagramMaxAgeMillis = 1_000,
        controlMaxAgeMillis = 1_000,
    )

    private fun fragmentPacket(fragmentId: Int, offset: Int): ByteArray {
        val packet = ByteArray(64)
        packet[0] = 0x45
        packet[2] = 0
        packet[3] = packet.size.toByte()
        packet[4] = (fragmentId ushr 8).toByte()
        packet[5] = fragmentId.toByte()
        val flagsAndOffset = if (offset == 0) 0x2000 else offset
        packet[6] = (flagsAndOffset ushr 8).toByte()
        packet[7] = flagsAndOffset.toByte()
        packet[9] = 17
        packet[12] = 10
        packet[15] = 2
        packet[16] = 1
        packet[17] = 1
        packet[18] = 1
        packet[19] = 1
        return packet
    }
}
