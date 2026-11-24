package dev.porta.android

import kotlin.math.absoluteValue

internal class ReconnectBackoff(clientId: String) {
    private val jitterMillis = (clientId.hashCode().toLong().absoluteValue % 250L)
    private var failures = 0

    /**
     * 250 ms before the first retry, so a session a restarting gateway ended
     * resumes at once, then doubling up to 30 s; per-device jitter spreads
     * reconnects after a gateway restart.
     */
    fun nextDelayMillis(): Long {
        val exponent = failures.coerceAtMost(7)
        failures++
        return (250L shl exponent).coerceAtMost(30_000L) + jitterMillis
    }

    fun reset() {
        failures = 0
    }
}
