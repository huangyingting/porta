package dev.porta.android

import java.util.concurrent.TimeUnit

internal data class ScheduledPacket(
    val lane: Int,
    val packet: PacketBuffer,
)

internal class FairLanePacketScheduler(
    private val laneQueues: List<BoundedPacketQueue>,
    private val signal: PacketQueueSignal,
    private val laneZeroBurst: Int = 4,
) {
    private var laneZeroBudget = laneZeroBurst
    private var nextDataLane = 1

    init {
        require(laneQueues.isNotEmpty())
        require(laneZeroBurst > 0)
    }

    @Synchronized
    fun pollNow(): ScheduledPacket? {
        if (laneZeroBudget > 0) {
            laneQueues[0].pollNow()?.let {
                laneZeroBudget--
                return ScheduledPacket(0, it)
            }
        }
        pollDataLane()?.let {
            laneZeroBudget = laneZeroBurst
            return it
        }
        laneQueues[0].pollNow()?.let {
            laneZeroBudget = (laneZeroBudget - 1).coerceAtLeast(0)
            return ScheduledPacket(0, it)
        }
        return null
    }

    fun poll(timeout: Long, unit: TimeUnit): ScheduledPacket? {
        val deadline = System.nanoTime() + unit.toNanos(timeout)
        while (true) {
            pollNow()?.let { return it }
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0L || !signal.await(remaining, TimeUnit.NANOSECONDS)) return null
        }
    }

    private fun pollDataLane(): ScheduledPacket? {
        if (laneQueues.size <= 1) return null
        repeat(laneQueues.size - 1) {
            val lane = nextDataLane
            nextDataLane = if (nextDataLane + 1 < laneQueues.size) nextDataLane + 1 else 1
            laneQueues[lane].pollNow()?.let { return ScheduledPacket(lane, it) }
        }
        return null
    }
}

internal class StableDataLaneRouter(
    private val laneCount: Int,
    private val isLaneReady: (Int) -> Boolean,
    private val queuedBytes: (Int) -> Int,
    private val clockNanos: () -> Long = System::nanoTime,
    private val maxFlowAssignments: Int = 4_096,
    private val flowIdleNanos: Long = TimeUnit.MINUTES.toNanos(2),
    private val pruneIntervalNanos: Long = TimeUnit.SECONDS.toNanos(10),
) {
    private data class Assignment(val lane: Int, val lastSeenNanos: Long)

    private val assignments = LinkedHashMap<PacketFlowKey, Assignment>(256, 0.75f, true)
    private var lastPruneNanos = Long.MIN_VALUE

    init {
        require(laneCount >= 2)
        require(maxFlowAssignments > 0)
        require(flowIdleNanos > 0)
        require(pruneIntervalNanos >= 0)
    }

    @Synchronized
    fun select(metadata: PacketMetadata): Int? {
        if (metadata.packetClass == PacketClass.CONTROL) return 0
        val now = clockNanos()
        pruneLocked(now)
        assignments[metadata.flow]?.let { assignment ->
            if (now - assignment.lastSeenNanos < flowIdleNanos &&
                isLaneReady(assignment.lane)
            ) {
                assignments[metadata.flow] = assignment.copy(lastSeenNanos = now)
                return assignment.lane
            }
            assignments.remove(metadata.flow)
        }
        val candidates = (1 until laneCount).filter(isLaneReady)
        if (candidates.isEmpty()) return null
        val start = (Integer.toUnsignedLong(metadata.hash) % candidates.size).toInt()
        var selected = candidates[start]
        var selectedBytes = queuedBytes(selected)
        for (offset in 1 until candidates.size) {
            val lane = candidates[(start + offset) % candidates.size]
            val bytes = queuedBytes(lane)
            if (bytes < selectedBytes) {
                selected = lane
                selectedBytes = bytes
            }
        }
        assignments[metadata.flow] = Assignment(selected, now)
        if (assignments.size > maxFlowAssignments) {
            assignments.entries.iterator().run {
                if (hasNext()) {
                    next()
                    remove()
                }
            }
        }
        return selected
    }

    @Synchronized
    fun assignmentCount(): Int = assignments.size

    private fun pruneLocked(nowNanos: Long) {
        if (lastPruneNanos != Long.MIN_VALUE &&
            nowNanos - lastPruneNanos < pruneIntervalNanos &&
            assignments.size < maxFlowAssignments
        ) {
            return
        }
        lastPruneNanos = nowNanos
        val iterator = assignments.entries.iterator()
        while (iterator.hasNext()) {
            if (nowNanos - iterator.next().value.lastSeenNanos >= flowIdleNanos) iterator.remove()
        }
    }
}

internal class AdaptiveLaneController(
    private val laneCount: Int = 4,
    private val pressureThreshold: Double = 0.65,
    private val blockedWriteThresholdMillis: Long = 75,
    private val blockedWritesRequired: Int = 3,
    private val scaleCooldownMillis: Long = 1_000,
) {
    private val desired = BooleanArray(laneCount)
    private var blockedWrites = 0
    private var lastScaleMillis = Long.MIN_VALUE

    init {
        require(laneCount >= 2)
        desired[0] = true
        desired[1] = true
    }

    @Synchronized
    fun observePressure(pressure: Double, nowMillis: Long = System.currentTimeMillis()): Int? =
        if (pressure >= pressureThreshold) activateNextLocked(nowMillis) else null

    @Synchronized
    fun observeBlockedWrite(durationMillis: Long, nowMillis: Long = System.currentTimeMillis()): Int? {
        blockedWrites = if (durationMillis >= blockedWriteThresholdMillis) blockedWrites + 1 else 0
        if (blockedWrites < blockedWritesRequired) return null
        blockedWrites = 0
        return activateNextLocked(nowMillis)
    }

    @Synchronized
    fun observeLaneFailure(nowMillis: Long = System.currentTimeMillis()): Int? =
        activateNextLocked(nowMillis, enforceCooldown = false)

    @Synchronized
    fun desiredLanes(): Set<Int> = desired.indices.filterTo(linkedSetOf()) { desired[it] }

    private fun activateNextLocked(nowMillis: Long, enforceCooldown: Boolean = true): Int? {
        if (enforceCooldown && lastScaleMillis != Long.MIN_VALUE &&
            nowMillis - lastScaleMillis < scaleCooldownMillis
        ) {
            return null
        }
        val lane = (2 until laneCount).firstOrNull { !desired[it] } ?: return null
        desired[lane] = true
        lastScaleMillis = nowMillis
        return lane
    }
}

internal class Http2PacketDispatcher(
    private val laneQueues: List<BoundedPacketQueue>,
    private val pendingQueue: BoundedPacketQueue,
    private val isLaneReady: (Int) -> Boolean,
    private val adaptiveLanes: AdaptiveLaneController,
    private val requestLaneActivation: (Int) -> Unit,
) {
    private val router = StableDataLaneRouter(
        laneCount = laneQueues.size,
        isLaneReady = isLaneReady,
        queuedBytes = { laneQueues[it].queuedBytes() },
    )

    @Synchronized
    fun offer(packet: PacketBuffer): Boolean = offer(packet, null)

    private fun offer(packet: PacketBuffer, queued: QueuedPacket?): Boolean {
        val metadata = classifyIPv4Packet(packet.bytes, packet.length)
        val lane = if (metadata.packetClass == PacketClass.CONTROL) {
            controlLane()
        } else {
            router.select(metadata)
        }
        val queue = lane?.let(laneQueues::get) ?: pendingQueue
        val accepted = if (queued == null) {
            queue.offer(packet, metadata.packetClass)
        } else {
            queue.offer(
                packet,
                metadata.packetClass,
                enqueuedNanos = queued.enqueuedNanos,
            )
        }
        if (!accepted) packet.release()
        if (lane == null || lane > 0) {
            adaptiveLanes.observePressure(queue.pressure())?.let(requestLaneActivation)
        }
        return accepted
    }

    @Synchronized
    fun laneBecameReady() {
        if ((1 until laneQueues.size).none(isLaneReady)) return
        val pending = pendingQueue.snapshot().packets
        for (ignored in 0 until pending) {
            val queued = pendingQueue.pollEntryNow() ?: break
            offer(queued.packet, queued)
        }
    }

    @Synchronized
    fun laneBecameUnavailable(source: BoundedPacketQueue) {
        source.discardForRecovery()
    }

    private fun controlLane(): Int? {
        if (isLaneReady(0)) return 0
        return (1 until laneQueues.size)
            .filter(isLaneReady)
            .minByOrNull { laneQueues[it].queuedBytes() }
    }
}
