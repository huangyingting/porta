package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Http2LaneRecoveryTest {
    @Test
    fun laneZeroAndOneDataLaneAreEnoughForPartialReadiness() {
        val state = Http2LaneRecoveryState<String>()
        state.markConnecting(0)
        state.markConnecting(1)
        assertTrue(state.markReady(1, "lease"))
        assertFalse(state.isPartiallyReady())

        assertTrue(state.markReady(0, "lease"))

        val snapshot = state.snapshot()
        assertTrue(snapshot.partiallyReady)
        assertTrue(state.hasBeenPartiallyReady())
        assertEquals(2, snapshot.activeLaneCount)
    }

    @Test
    fun healthyExtraLaneKeepsTunnelReadyWhileAnotherDataLaneRecovers() {
        var now = 0L
        val state = Http2LaneRecoveryState<String>(
            requiredUnavailableTimeoutMillis = 5_000,
            clockMillis = { now },
        )
        state.markReady(0, "lease")
        state.markReady(1, "lease")
        state.markReady(2, "lease")

        state.markFailure(1, permanent = false)
        now = 10_000

        assertTrue(state.isPartiallyReady())
        assertFalse(state.shouldTerminate())
        assertEquals(Http2LanePhase.READY, state.snapshot().phases[2])
    }

    @Test
    fun requiredLaneOutageExpiresButSuccessfulRecoveryClearsDeadline() {
        var now = 1_000L
        val state = Http2LaneRecoveryState<String>(
            requiredUnavailableTimeoutMillis = 5_000,
            clockMillis = { now },
        )
        state.markReady(0, "lease")
        state.markReady(1, "lease")
        state.markFailure(0, permanent = false)
        now = 5_999
        assertFalse(state.shouldTerminate())
        now = 6_000
        assertTrue(state.shouldTerminate())

        state.markReady(0, "lease")

        assertFalse(state.shouldTerminate())
        assertTrue(state.isPartiallyReady())
    }

    @Test
    fun allDataLanesMayRecoverUntilRequiredTimeout() {
        var now = 0L
        val state = Http2LaneRecoveryState<String>(
            requiredUnavailableTimeoutMillis = 2_000,
            clockMillis = { now },
        )
        state.markReady(0, "lease")
        state.markReady(1, "lease")
        state.markFailure(1, permanent = false)
        now = 1_999
        assertFalse(state.shouldTerminate())
        now = 2_000
        assertTrue(state.shouldTerminate())
    }

    @Test
    fun configurationMismatchIsPermanent() {
        val state = Http2LaneRecoveryState<String>()
        assertTrue(state.markReady(0, "lease-a"))
        assertFalse(state.markReady(1, "lease-b"))
        assertTrue(state.shouldTerminate())
        assertTrue(state.snapshot().permanentFailure)
    }

    @Test
    fun laneReconnectBackoffIsBoundedAndResetsAfterReady() {
        val state = Http2LaneRecoveryState<String>()
        val delays = List(8) { state.markFailure(1, permanent = false) }
        assertEquals(1_000L, delays.first())
        assertEquals(30_000L, delays.last())

        state.markReady(1, "lease")

        assertEquals(1_000L, state.markFailure(1, permanent = false))
        assertEquals(9, state.snapshot().reconnects[1])
    }
}
