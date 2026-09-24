package dev.porta.android

import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import portamobile.NativeFailureKind
import portamobile.nativeFailureKind

class NativeDialRecoveryTest {
    @Test
    fun networkInvalidationChecksAndCancelsUnderTheServiceLifecycleLock() {
        val lifecycleLock = Any()
        val active = AtomicBoolean(true)
        var cancellations = 0
        assertTrue(
            invalidateTransportAttempt(
                lifecycleLock,
                active,
                isCurrentAttempt = {
                    assertTrue(Thread.holdsLock(lifecycleLock))
                    true
                },
                cancel = {
                    assertTrue(Thread.holdsLock(lifecycleLock))
                    assertFalse(active.get())
                    cancellations++
                },
            ),
        )
        assertEquals(1, cancellations)
        assertFalse(active.get())
    }

    @Test
    fun retiredNetworkCallbacksCannotCancelOrSelectANetworkForANewerAttempt() {
        val lifecycleLock = Any()
        for ((active, current) in listOf(true to false, false to true, false to false)) {
            assertFalse(
                invalidateTransportAttempt(
                    lifecycleLock,
                    AtomicBoolean(active),
                    isCurrentAttempt = { current },
                    cancel = { throw AssertionError("Stale callback mutated the current attempt") },
                ),
            )
        }
    }

    @Test
    fun repeatedNetworkInvalidationsCancelAnAttemptOnlyOnce() {
        val lifecycleLock = Any()
        val active = AtomicBoolean(true)
        var cancellations = 0
        repeat(2) {
            invalidateTransportAttempt(lifecycleLock, active, { true }) { cancellations++ }
        }
        assertEquals(1, cancellations)
    }

    @Test
    fun staleReaderFailureDoesNotOverrideNativeTimeoutFallbackAcrossRetries() {
        val failedReader = IOException("TUN reader stopped")
        repeat(3) {
            assertFalse(hasNewVpnReaderFailure(failedReader, failedReader))
        }
    }

    @Test
    fun readerFailureDuringDialRequiresRetryInsteadOfPermanentCancellation() {
        val failedReader = IOException("TUN reader stopped")
        assertTrue(hasNewVpnReaderFailure(null, failedReader))
        assertTrue(hasNewVpnReaderFailure(IOException("previous reader"), failedReader))
    }

    @Test
    fun healthyOrReplacedReaderDoesNotOverrideNativeFailureClassification() {
        assertFalse(hasNewVpnReaderFailure(null, null))
        assertFalse(hasNewVpnReaderFailure(IOException("previous reader"), null))
    }

    @Test
    fun establishedNativeFailuresKeepTheirTransportClassification() {
        assertEquals(
            NativeFailureKind.TRANSPORT_UNAVAILABLE,
            nativeFailureKind("transport unavailable: gateway does not support HTTP/3"),
        )
        assertEquals(
            NativeFailureKind.RETRYABLE,
            nativeFailureKind("retryable: gateway closed the connection"),
        )
        assertEquals(NativeFailureKind.RETRYABLE, nativeFailureKind("tunnel is closed"))
        assertEquals(
            NativeFailureKind.PERMANENT,
            nativeFailureKind("gateway returned an invalid tunnel response"),
        )
    }
}
