package dev.porta.android

import java.io.IOException
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

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
}
