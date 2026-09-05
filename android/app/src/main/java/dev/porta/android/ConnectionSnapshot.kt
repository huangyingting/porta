package dev.porta.android

import java.util.concurrent.atomic.AtomicLong

internal data class ConnectionDetails(
    val mtu: Int,
    val automaticMtu: Boolean,
    val mtuCeiling: Int? = null,
    val address: String = "",
    val dns: String = "",
    val transport: String = "",
    val deliveryMode: String? = null,
    val networkType: String? = null,
    val setupDurationMillis: Long = 0,
    val appVersion: String = "",
    val protocolVersion: String = "",
)

internal data class ConnectionAttemptToken internal constructor(
    val generation: Long,
    val attemptId: Long,
)

internal class ConnectionDetailsState {
    private val nextAttemptId = AtomicLong(0)
    private val lock = Any()
    private var activeAttempt: ConnectionAttemptToken? = null
    private var currentDetails: ConnectionDetails? = null

    fun startAttempt(generation: Long): ConnectionAttemptToken {
        val token = ConnectionAttemptToken(generation, nextAttemptId.incrementAndGet())
        synchronized(lock) {
            activeAttempt = token
            currentDetails = null
        }
        return token
    }

    fun publish(token: ConnectionAttemptToken, details: ConnectionDetails): Boolean = synchronized(lock) {
        if (activeAttempt == token) {
            currentDetails = details
            true
        } else {
            false
        }
    }

    fun clear(token: ConnectionAttemptToken): Boolean = synchronized(lock) {
        if (activeAttempt == token) {
            activeAttempt = null
            currentDetails = null
            true
        } else {
            false
        }
    }

    fun clearAll() {
        synchronized(lock) {
            activeAttempt = null
            currentDetails = null
        }
    }

    fun current(): ConnectionDetails? = synchronized(lock) { currentDetails }
}

private val currentConnectionDetailsState = ConnectionDetailsState()

internal fun beginConnectionAttempt(generation: Long): ConnectionAttemptToken =
    currentConnectionDetailsState.startAttempt(generation)

internal fun publishConnectionDetails(token: ConnectionAttemptToken, details: ConnectionDetails): Boolean =
    currentConnectionDetailsState.publish(token, details)

internal fun clearConnectionDetails(token: ConnectionAttemptToken): Boolean =
    currentConnectionDetailsState.clear(token)

internal fun resetConnectionDetailsState() {
    currentConnectionDetailsState.clearAll()
}

internal fun TunnelService.Companion.currentConnectionDetails(): ConnectionDetails? =
    currentConnectionDetailsState.current()
