package dev.porta.android

import java.util.concurrent.atomic.AtomicBoolean
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLProtocolException

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

internal enum class NativeFailureKind { TRANSPORT_UNAVAILABLE, RETRYABLE, PERMANENT }

internal fun nativeFailureKind(message: String): NativeFailureKind = when {
    message.startsWith("transport unavailable: ") -> NativeFailureKind.TRANSPORT_UNAVAILABLE
    message.startsWith("retryable: ") || message == "tunnel is closed" -> NativeFailureKind.RETRYABLE
    else -> NativeFailureKind.PERMANENT
}

internal fun isPermanentTlsFailure(error: Throwable): Boolean =
    generateSequence(error) { it.cause?.takeUnless { cause -> cause === it } }.take(16).any {
        it is CertificateException || it is SSLHandshakeException ||
            it is SSLPeerUnverifiedException || it is SSLProtocolException
    }
