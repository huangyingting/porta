package dev.porta.android

import java.io.IOException
import java.net.SocketTimeoutException
import java.security.cert.CertificateException
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

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
    }

    @Test
    fun retiredCallbacksCannotCancelOrSelectANetworkForANewerAttempt() {
        for ((active, current) in listOf(true to false, false to true, false to false)) {
            val flag = AtomicBoolean(active)
            assertFalse(
                invalidateTransportAttempt(
                    Any(), flag, { current },
                    { throw AssertionError("Stale callback mutated the current attempt") },
                ),
            )
            assertEquals(active, flag.get())
        }
    }

    @Test
    fun repeatedInvalidationsCancelOnlyOnce() {
        val lock = Any()
        val active = AtomicBoolean(true)
        var cancellations = 0
        repeat(2) { invalidateTransportAttempt(lock, active, { true }) { cancellations++ } }
        assertEquals(1, cancellations)
    }

    @Test
    fun establishedFailuresKeepTheirNativeClassification() {
        assertEquals(NativeFailureKind.TRANSPORT_UNAVAILABLE, nativeFailureKind("transport unavailable: UDP blocked"))
        assertEquals(NativeFailureKind.RETRYABLE, nativeFailureKind("retryable: connection closed"))
        assertEquals(NativeFailureKind.RETRYABLE, nativeFailureKind("tunnel is closed"))
        assertEquals(NativeFailureKind.PERMANENT, nativeFailureKind("invalid tunnel response"))
        assertEquals(NativeFailureKind.PERMANENT, nativeFailureKind("certificate verification: retryable: rejected"))
    }

    @Test
    fun http2TlsFailuresDoNotRetryLikeNetworkFailures() {
        assertTrue(isPermanentTlsFailure(SSLHandshakeException("certificate invalid")))
        assertTrue(isPermanentTlsFailure(SSLPeerUnverifiedException("hostname mismatch")))
        assertTrue(isPermanentTlsFailure(IOException("TLS", CertificateException("expired"))))
        assertFalse(isPermanentTlsFailure(SocketTimeoutException("network timeout")))
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
}
