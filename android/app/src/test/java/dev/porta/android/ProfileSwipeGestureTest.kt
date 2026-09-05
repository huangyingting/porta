package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileSwipeGestureTest {
    private fun gesture() = ProfileSwipeGesture(8f, 80f).apply { begin(100f, 100f) }

    @Test
    fun rightEditsAndLeftDeletesOnlyPastTheThreshold() {
        val right = gesture()
        right.move(170f, 105f)
        assertTrue(right.isHorizontal)
        assertFalse(right.isArmed)
        assertNull(right.finish(179f, 105f))
        assertEquals(ProfileSwipeAction.EDIT, gesture().finish(180f, 105f))
        assertEquals(ProfileSwipeAction.DELETE, gesture().finish(20f, 105f))
    }

    @Test
    fun verticalScrollCannotTurnIntoAProfileAction() {
        val swipe = gesture()
        swipe.move(102f, 120f)
        swipe.move(250f, 122f)
        assertFalse(swipe.isHorizontal)
        assertEquals(0f, swipe.displacement, 0f)
        assertNull(swipe.finish(250f, 122f))
    }

    @Test
    fun tapsJitterAndDiagonalMovementDoNotTriggerActions() {
        val tap = gesture()
        tap.move(106f, 104f)
        assertTrue(tap.isTap)
        assertNull(tap.finish(106f, 104f))
        val diagonal = gesture()
        diagonal.move(200f, 190f)
        assertFalse(diagonal.isTap)
        assertNull(diagonal.finish(200f, 190f))
        assertNull(gesture().finish(110f, 250f))
    }

    @Test
    fun returningBelowThresholdOrMovingVerticallyCancelsTheAction() {
        val swipe = gesture()
        swipe.move(200f, 102f)
        assertTrue(swipe.isArmed)
        assertNull(swipe.finish(120f, 103f))
        val diagonal = gesture()
        diagonal.move(200f, 102f)
        assertNull(diagonal.finish(200f, 190f))
    }

    @Test
    fun cancellationAndMultiTouchAbortUntilANewGestureBegins() {
        val swipe = gesture()
        swipe.move(200f, 102f)
        swipe.cancel()
        assertNull(swipe.finish(260f, 102f))
        assertFalse(swipe.isHorizontal)
        swipe.begin(300f, 200f)
        assertEquals(ProfileSwipeAction.DELETE, swipe.finish(210f, 202f))
    }

    @Test
    fun releaseRunsAtMostOneActionAndUsesTheFinalDirection() {
        val swipe = gesture()
        swipe.move(200f, 100f)
        assertEquals(ProfileSwipeAction.DELETE, swipe.finish(0f, 100f))
        assertNull(swipe.finish(0f, 100f))
    }

    @Test
    fun halfCardDistanceTriggersAcrossPhoneAndTabletWidths() {
        for (width in listOf(296f, 342f, 744f)) {
            val distance = profileSwipeActionDistance(width, 8f)
            assertEquals(width / 2f, distance, 0f)
            for ((direction, expected) in listOf(1f to ProfileSwipeAction.EDIT, -1f to ProfileSwipeAction.DELETE)) {
                val partial = ProfileSwipeGesture(8f, distance).apply { begin(400f, 100f) }
                partial.move(400f + direction * (distance - 1f), 102f)
                assertFalse(partial.isArmed)
                assertNull(partial.finish(400f + direction * (distance - 1f), 102f))
                val committed = ProfileSwipeGesture(8f, distance).apply { begin(400f, 100f) }
                assertEquals(expected, committed.finish(400f + direction * distance, 102f))
            }
        }
    }

    @Test
    fun armedGestureIsStickyAcrossASmallRetreat() {
        val swipe = ProfileSwipeGesture(8f, 100f).apply { begin(200f, 100f) }
        swipe.move(300f, 102f)
        assertTrue(swipe.isArmed)
        swipe.move(290f, 102f)
        assertTrue(swipe.isArmed)
        assertEquals(ProfileSwipeAction.EDIT, swipe.finish(290f, 102f))
    }

    @Test
    fun retreatingWellBelowTheHalfCardThresholdDisarmsTheGesture() {
        val swipe = ProfileSwipeGesture(8f, 100f).apply { begin(200f, 100f) }
        swipe.move(300f, 102f)
        swipe.move(275f, 102f)
        assertFalse(swipe.isArmed)
        assertNull(swipe.finish(275f, 102f))
    }
}
