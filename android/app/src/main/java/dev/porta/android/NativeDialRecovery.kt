package dev.porta.android

import java.util.concurrent.atomic.AtomicBoolean

// A failed reader remains attached until a transport connects and can replace its VPN.
// Only a new failure can have canceled this dial; an existing one must allow H2 fallback.
internal fun hasNewVpnReaderFailure(beforeDial: Exception?, afterDial: Exception?): Boolean =
    afterDial != null && afterDial !== beforeDial

internal fun invalidateTransportAttempt(
    lifecycleLock: Any,
    attemptActive: AtomicBoolean,
    isCurrentAttempt: () -> Boolean,
    cancel: () -> Unit,
): Boolean = synchronized(lifecycleLock) {
    if (!isCurrentAttempt() || !attemptActive.compareAndSet(true, false)) {
        false
    } else {
        // Keep validation and cancellation atomic with publishing replacement native handles.
        cancel()
        true
    }
}
