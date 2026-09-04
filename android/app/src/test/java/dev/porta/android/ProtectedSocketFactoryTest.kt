package dev.porta.android

import java.io.IOException
import java.net.Socket
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectedSocketFactoryTest {
    @Test
    fun closesSocketWhenProtectionBindingOrConnectionFails() {
        for (failure in listOf(IOException("bind failed"), IllegalStateException("protection failed"))) {
            val socket = Socket()
            try {
                configureSocket(socket) { throw failure }
                org.junit.Assert.fail("Expected setup failure")
            } catch (error: Exception) {
                assertSame(failure, error)
                assertTrue(socket.isClosed)
            }
        }
    }

    @Test
    fun leavesSuccessfulSocketOpenForCaller() {
        Socket().use { socket ->
            assertSame(socket, configureSocket(socket) {})
            assertFalse(socket.isClosed)
        }
    }

    @Test
    fun preservesOriginalFailureWhenCloseAlsoFails() {
        val failure = IOException("connect failed")
        val closeFailure = IOException("close failed")
        val socket = object : Socket() {
            override fun close() = throw closeFailure
        }
        try {
            configureSocket(socket) { throw failure }
            org.junit.Assert.fail("Expected setup failure")
        } catch (error: IOException) {
            assertSame(failure, error)
            assertSame(closeFailure, error.suppressed.single())
        }
    }
}
