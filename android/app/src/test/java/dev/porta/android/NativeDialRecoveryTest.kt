package dev.porta.android

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import portamobile.NativeFailureKind
import portamobile.nativeFailureKind

class NativeDialRecoveryTest {
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
