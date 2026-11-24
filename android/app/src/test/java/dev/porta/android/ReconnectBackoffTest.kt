package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ReconnectBackoffTest {
    @Test
    fun growsToCapAndResets() {
        val backoff = ReconnectBackoff("android-test")
        val delays = List(9) { backoff.nextDelayMillis() }

        assertTrue(delays.zipWithNext().all { (first, second) -> second >= first })
        assertTrue(delays.first() in 250L..499L)
        assertTrue(delays.last() in 30_000L..30_249L)

        backoff.reset()
        assertEquals(delays.first(), backoff.nextDelayMillis())
    }
}
