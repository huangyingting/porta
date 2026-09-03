package dev.porta.android

import kotlin.math.absoluteValue

internal class ReconnectBackoff(clientId: String) {
    private val jitterMillis = (clientId.hashCode().toLong().absoluteValue % 1_000L)
    private var failures = 0

    fun nextDelayMillis(): Long {
        val exponent = failures.coerceAtMost(5)
        failures++
        return (1_000L shl exponent).coerceAtMost(30_000L) + jitterMillis
    }

    fun reset() {
        failures = 0
    }
}
