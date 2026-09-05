package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionSnapshotStateTest {
    @Test
    fun staleAttemptCannotPublishAfterNewAttemptStarts() {
        val state = ConnectionDetailsState()
        val first = state.startAttempt(1)

        assertTrue(state.publish(first, ConnectionDetails(mtu = 1360, automaticMtu = true)))
        assertEquals(1360, state.current()?.mtu)

        val second = state.startAttempt(2)

        assertNull(state.current())
        assertFalse(state.publish(first, ConnectionDetails(mtu = 1280, automaticMtu = false)))
        assertNull(state.current())
        assertTrue(state.publish(second, ConnectionDetails(mtu = 1300, automaticMtu = false)))
        assertEquals(1300, state.current()?.mtu)
    }

    @Test
    fun staleAttemptCannotClearCurrentSnapshot() {
        val state = ConnectionDetailsState()
        val first = state.startAttempt(1)
        val second = state.startAttempt(1)

        assertTrue(state.publish(second, ConnectionDetails(mtu = 1300, automaticMtu = false)))
        assertFalse(state.clear(first))
        assertEquals(1300, state.current()?.mtu)
        assertTrue(state.clear(second))
        assertNull(state.current())
    }
}
