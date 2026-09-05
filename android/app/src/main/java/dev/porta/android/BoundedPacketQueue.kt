package dev.porta.android

import java.util.EnumMap
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal data class PacketQueueConfig(
    val maxPackets: Int,
    val maxBytes: Int,
    val tcpMaxAgeMillis: Long,
    val datagramMaxAgeMillis: Long,
    val controlMaxAgeMillis: Long,
    val replacementPolicy: PacketQueueReplacementPolicy = PacketQueueReplacementPolicy.CLASS_AWARE,
) {
    init {
        require(maxPackets > 0)
        require(maxBytes > 0)
        require(tcpMaxAgeMillis >= 0)
        require(datagramMaxAgeMillis >= 0)
        require(controlMaxAgeMillis >= 0)
    }
}

internal enum class PacketQueueReplacementPolicy {
    CLASS_AWARE,
    DROP_OLDEST,
}

internal data class PacketQueueSnapshot(
    val packets: Int,
    val bytes: Int,
    val highWaterPackets: Int,
    val highWaterBytes: Int,
    val oldestAgeMillis: Long,
    val enqueued: Long,
    val dequeued: Long,
    val expiredDrops: Long,
    val overflowDrops: Long,
    val tailDrops: Long,
    val oldestDrops: Long,
    val recoveryDrops: Long,
    val droppedByClass: Map<PacketClass, Long>,
) {
    val totalDrops: Long
        get() = expiredDrops + overflowDrops + tailDrops + oldestDrops + recoveryDrops
}

internal data class QueuedPacket(
    val packet: PacketBuffer,
    val enqueuedNanos: Long,
)

internal class PacketBuffer private constructor(
    val bytes: ByteArray,
    val length: Int,
    private val recycler: ((ByteArray) -> Unit)?,
) {
    private val released = AtomicBoolean(false)

    init {
        require(length in 0..bytes.size)
    }

    fun release() {
        if (released.compareAndSet(false, true)) recycler?.invoke(bytes)
    }

    fun copyBytes(): ByteArray = bytes.copyOf(length)

    companion object {
        fun wrap(bytes: ByteArray, length: Int = bytes.size): PacketBuffer =
            PacketBuffer(bytes, length, null)

        internal fun pooled(bytes: ByteArray, length: Int, pool: PacketBufferPool): PacketBuffer =
            PacketBuffer(bytes, length, pool::recycle)
    }
}

internal class PacketBufferPool(
    private val bufferSize: Int = 65_535,
    private val maxCachedBuffers: Int = 64,
) {
    private val buffers = ArrayDeque<ByteArray>()

    init {
        require(bufferSize > 0)
        require(maxCachedBuffers >= 0)
    }

    @Synchronized
    fun acquire(): ByteArray = if (buffers.isEmpty()) ByteArray(bufferSize) else buffers.removeLast()

    @Synchronized
    internal fun recycle(buffer: ByteArray) {
        if (buffer.size == bufferSize && buffers.size < maxCachedBuffers) buffers.addLast(buffer)
    }

    @Synchronized
    fun cachedBuffers(): Int = buffers.size
}

internal class PacketQueueSignal {
    private val semaphore = Semaphore(0)

    fun signal() {
        if (semaphore.availablePermits() == 0) semaphore.release()
    }

    fun await(timeout: Long, unit: TimeUnit): Boolean = semaphore.tryAcquire(timeout, unit)
}

internal class BoundedPacketQueue(
    private val config: PacketQueueConfig,
    private val signal: PacketQueueSignal? = null,
    private val clockNanos: () -> Long = System::nanoTime,
) {
    private data class Entry(
        val packet: PacketBuffer,
        val packetClass: PacketClass,
        val enqueuedNanos: Long,
    )

    private val lock = ReentrantLock()
    private val notEmpty = lock.newCondition()
    private val entries = ArrayList<Entry>(config.maxPackets)
    private var head = 0
    private var byteCount = 0
    private var highWaterPackets = 0
    private var highWaterBytes = 0
    private var enqueued = 0L
    private var dequeued = 0L
    private var expiredDrops = 0L
    private var overflowDrops = 0L
    private var tailDrops = 0L
    private var oldestDrops = 0L
    private var recoveryDrops = 0L
    private val droppedByClass = LongArray(PacketClass.entries.size)

    fun offer(
        packet: PacketBuffer,
        packetClass: PacketClass = classifyIPv4Packet(packet.bytes, packet.length).packetClass,
        nowNanos: Long = clockNanos(),
        enqueuedNanos: Long = nowNanos,
    ): Boolean = lock.withLock {
        dropExpiredLocked(nowNanos)
        if (packet.length > config.maxBytes) {
            recordIncomingDropLocked(packetClass)
            return false
        }
        while (!fitsLocked(packet.length)) {
            val victim = oldestReplaceableLocked(packetClass)
            if (victim < 0) {
                recordIncomingDropLocked(packetClass)
                return false
            }
            removeLocked(victim, PacketDropReason.OLDEST)
        }
        entries.add(Entry(packet, packetClass, enqueuedNanos))
        byteCount += packet.length
        enqueued++
        highWaterPackets = maxOf(highWaterPackets, sizeLocked())
        highWaterBytes = maxOf(highWaterBytes, byteCount)
        notEmpty.signal()
        signal?.signal()
        true
    }

    fun poll(timeout: Long, unit: TimeUnit): PacketBuffer? {
        var remaining = unit.toNanos(timeout)
        lock.withLock {
            while (true) {
                dropExpiredLocked(clockNanos())
                removeHeadEntryLocked()?.let { return it.packet }
                if (remaining <= 0L) return null
                remaining = notEmpty.awaitNanos(remaining)
            }
        }
    }

    fun pollNow(nowNanos: Long = clockNanos()): PacketBuffer? = lock.withLock {
        dropExpiredLocked(nowNanos)
        removeHeadEntryLocked()?.packet
    }

    internal fun pollEntryNow(nowNanos: Long = clockNanos()): QueuedPacket? = lock.withLock {
        dropExpiredLocked(nowNanos)
        removeHeadEntryLocked()?.let {
            QueuedPacket(it.packet, it.enqueuedNanos)
        }
    }

    fun drainTo(
        destination: MutableList<PacketBuffer>,
        maximum: Int,
        maximumBytes: Int = Int.MAX_VALUE,
    ): Int = lock.withLock {
        require(maximum >= 0)
        require(maximumBytes > 0)
        dropExpiredLocked(clockNanos())
        var count = 0
        var bytes = destination.sumOf(PacketBuffer::length)
        while (count < maximum) {
            val next = entries.getOrNull(head)?.packet ?: break
            if (destination.isNotEmpty() && bytes + next.length > maximumBytes) break
            val packet = removeHeadEntryLocked()?.packet ?: break
            destination.add(packet)
            bytes += packet.length
            count++
        }
        count
    }

    fun clear() = lock.withLock {
        for (index in head until entries.size) entries[index].packet.release()
        entries.clear()
        head = 0
        byteCount = 0
    }

    fun discardForRecovery() = lock.withLock {
        for (index in head until entries.size) {
            val entry = entries[index]
            droppedByClass[entry.packetClass.ordinal]++
            recoveryDrops++
            entry.packet.release()
        }
        entries.clear()
        head = 0
        byteCount = 0
    }

    fun snapshot(nowNanos: Long = clockNanos()): PacketQueueSnapshot = lock.withLock {
        dropExpiredLocked(nowNanos)
        val oldestAge = entries.getOrNull(head)?.let {
            TimeUnit.NANOSECONDS.toMillis((nowNanos - it.enqueuedNanos).coerceAtLeast(0L))
        } ?: 0L
        PacketQueueSnapshot(
            packets = sizeLocked(),
            bytes = byteCount,
            highWaterPackets = highWaterPackets,
            highWaterBytes = highWaterBytes,
            oldestAgeMillis = oldestAge,
            enqueued = enqueued,
            dequeued = dequeued,
            expiredDrops = expiredDrops,
            overflowDrops = overflowDrops,
            tailDrops = tailDrops,
            oldestDrops = oldestDrops,
            recoveryDrops = recoveryDrops,
            droppedByClass = EnumMap<PacketClass, Long>(PacketClass::class.java).apply {
                PacketClass.entries.forEach { put(it, droppedByClass[it.ordinal]) }
            },
        )
    }

    fun queuedBytes(): Int = lock.withLock { byteCount }

    fun pressure(): Double = lock.withLock {
        maxOf(
            sizeLocked().toDouble() / config.maxPackets,
            byteCount.toDouble() / config.maxBytes,
        )
    }

    private fun fitsLocked(packetBytes: Int): Boolean =
        sizeLocked() < config.maxPackets && byteCount + packetBytes <= config.maxBytes

    private fun removeHeadEntryLocked(): Entry? {
        if (head >= entries.size) {
            resetLocked()
            return null
        }
        val entry = entries[head]
        head++
        byteCount -= entry.packet.length
        dequeued++
        compactLocked()
        return entry
    }

    private fun dropExpiredLocked(nowNanos: Long) {
        var index = head
        while (index < entries.size) {
            val entry = entries[index]
            val maxAge = maxAgeNanos(entry.packetClass)
            if (maxAge == 0L || nowNanos - entry.enqueuedNanos < maxAge) {
                index++
            } else {
                removeLocked(index, PacketDropReason.EXPIRED)
            }
        }
    }

    private fun oldestReplaceableLocked(incoming: PacketClass): Int {
        if (config.replacementPolicy == PacketQueueReplacementPolicy.DROP_OLDEST) {
            return if (head < entries.size) head else -1
        }
        for (index in head until entries.size) {
            if (entries[index].packetClass == PacketClass.DATAGRAM) return index
        }
        if (incoming == PacketClass.CONTROL) {
            for (index in head until entries.size) {
                if (entries[index].packetClass == PacketClass.CONTROL) return index
            }
        }
        return -1
    }

    private fun removeLocked(index: Int, reason: PacketDropReason) {
        val removed = entries.removeAt(index)
        byteCount -= removed.packet.length
        droppedByClass[removed.packetClass.ordinal]++
        when (reason) {
            PacketDropReason.EXPIRED -> expiredDrops++
            PacketDropReason.OLDEST -> oldestDrops++
        }
        removed.packet.release()
        if (head >= entries.size) resetLocked()
    }

    private fun recordIncomingDropLocked(packetClass: PacketClass) {
        droppedByClass[packetClass.ordinal]++
        if (packetClass == PacketClass.TCP) tailDrops++ else overflowDrops++
    }

    private fun maxAgeNanos(packetClass: PacketClass): Long = TimeUnit.MILLISECONDS.toNanos(
        when (packetClass) {
            PacketClass.TCP -> config.tcpMaxAgeMillis
            PacketClass.DATAGRAM -> config.datagramMaxAgeMillis
            PacketClass.CONTROL -> config.controlMaxAgeMillis
        },
    )

    private fun sizeLocked(): Int = entries.size - head

    private fun compactLocked() {
        if (head == 0 || (head < 64 && head * 2 < entries.size)) return
        entries.subList(0, head).clear()
        head = 0
    }

    private fun resetLocked() {
        entries.clear()
        head = 0
        byteCount = 0
    }

    private enum class PacketDropReason {
        EXPIRED,
        OLDEST,
    }
}
