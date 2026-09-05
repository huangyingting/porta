package dev.porta.android

internal enum class Http2LanePhase {
    IDLE,
    CONNECTING,
    READY,
    BACKOFF,
    PERMANENT_FAILURE,
}

internal data class Http2LaneSnapshot(
    val phases: List<Http2LanePhase>,
    val activeLaneCount: Int,
    val reconnects: List<Int>,
    val partiallyReady: Boolean,
    val permanentFailure: Boolean,
)

internal class Http2LaneRecoveryState<C>(
    private val laneCount: Int = 4,
    private val requiredUnavailableTimeoutMillis: Long = 20_000,
    private val clockMillis: () -> Long = System::currentTimeMillis,
) {
    private val phases = Array(laneCount) { Http2LanePhase.IDLE }
    private val reconnects = IntArray(laneCount)
    private val consecutiveFailures = IntArray(laneCount)
    private var expectedConfiguration: C? = null
    private var permanentFailure = false
    private var everPartiallyReady = false
    private var laneZeroUnavailableSince: Long? = null
    private var dataUnavailableSince: Long? = null

    init {
        require(laneCount >= 2)
        require(requiredUnavailableTimeoutMillis > 0)
    }

    @Synchronized
    fun markConnecting(lane: Int) {
        requireLane(lane)
        phases[lane] = Http2LanePhase.CONNECTING
    }

    @Synchronized
    fun markReady(lane: Int, configuration: C): Boolean {
        requireLane(lane)
        val expected = expectedConfiguration
        if (expected != null && expected != configuration) {
            phases[lane] = Http2LanePhase.PERMANENT_FAILURE
            permanentFailure = true
            return false
        }
        if (expected == null) expectedConfiguration = configuration
        phases[lane] = Http2LanePhase.READY
        consecutiveFailures[lane] = 0
        updateRequiredAvailabilityLocked(clockMillis())
        if (isPartiallyReadyLocked()) everPartiallyReady = true
        return true
    }

    @Synchronized
    fun markFailure(lane: Int, permanent: Boolean): Long {
        requireLane(lane)
        val now = clockMillis()
        reconnects[lane]++
        if (permanent) {
            phases[lane] = Http2LanePhase.PERMANENT_FAILURE
            permanentFailure = true
            updateRequiredAvailabilityLocked(now)
            return 0L
        }
        phases[lane] = Http2LanePhase.BACKOFF
        val exponent = consecutiveFailures[lane].coerceAtMost(5)
        consecutiveFailures[lane]++
        updateRequiredAvailabilityLocked(now)
        return (1_000L shl exponent).coerceAtMost(30_000L)
    }

    @Synchronized
    fun isReady(lane: Int): Boolean {
        requireLane(lane)
        return phases[lane] == Http2LanePhase.READY
    }

    @Synchronized
    fun isPartiallyReady(): Boolean = isPartiallyReadyLocked()

    @Synchronized
    fun hasBeenPartiallyReady(): Boolean = everPartiallyReady

    @Synchronized
    fun shouldTerminate(nowMillis: Long = clockMillis()): Boolean {
        if (permanentFailure) return true
        if (!everPartiallyReady) return false
        val laneZeroExpired = laneZeroUnavailableSince?.let {
            nowMillis - it >= requiredUnavailableTimeoutMillis
        } == true
        val dataExpired = dataUnavailableSince?.let {
            nowMillis - it >= requiredUnavailableTimeoutMillis
        } == true
        return laneZeroExpired || dataExpired
    }

    @Synchronized
    fun snapshot(): Http2LaneSnapshot = Http2LaneSnapshot(
        phases = phases.toList(),
        activeLaneCount = phases.count { it == Http2LanePhase.READY },
        reconnects = reconnects.toList(),
        partiallyReady = isPartiallyReadyLocked(),
        permanentFailure = permanentFailure,
    )

    private fun updateRequiredAvailabilityLocked(nowMillis: Long) {
        laneZeroUnavailableSince = if (phases[0] == Http2LanePhase.READY) {
            null
        } else {
            laneZeroUnavailableSince ?: nowMillis
        }
        dataUnavailableSince = if ((1 until laneCount).any { phases[it] == Http2LanePhase.READY }) {
            null
        } else {
            dataUnavailableSince ?: nowMillis
        }
    }

    private fun isPartiallyReadyLocked(): Boolean =
        phases[0] == Http2LanePhase.READY &&
            (1 until laneCount).any { phases[it] == Http2LanePhase.READY }

    private fun requireLane(lane: Int) {
        require(lane in 0 until laneCount)
    }
}
