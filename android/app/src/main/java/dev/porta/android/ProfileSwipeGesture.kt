package dev.porta.android

import kotlin.math.abs

internal enum class ProfileSwipeAction { EDIT, DELETE }

internal fun profileSwipeActionDistance(cardWidth: Float, touchSlop: Float): Float =
    maxOf(cardWidth * 0.5f, touchSlop + 1f)

internal class ProfileSwipeGesture(
    private val touchSlop: Float,
    private val actionDistance: Float,
) {
    private enum class Axis { PENDING, HORIZONTAL, VERTICAL, CANCELLED }

    private var axis = Axis.CANCELLED
    private var startX = 0f
    private var startY = 0f
    private var moved = false
    private var armedDirection = 0
    var displacement = 0f
        private set
    val isHorizontal: Boolean get() = axis == Axis.HORIZONTAL
    val isTap: Boolean get() = axis == Axis.PENDING && !moved
    val isArmed: Boolean get() = isHorizontal && armedDirection != 0

    init {
        require(touchSlop > 0 && actionDistance > touchSlop)
    }

    fun begin(x: Float, y: Float) {
        startX = x
        startY = y
        displacement = 0f
        moved = false
        armedDirection = 0
        axis = Axis.PENDING
    }

    fun move(x: Float, y: Float) {
        if (axis == Axis.CANCELLED || axis == Axis.VERTICAL) return
        val dx = x - startX
        val dy = y - startY
        if (abs(dx) > touchSlop || abs(dy) > touchSlop) moved = true
        if (axis == Axis.PENDING) {
            if (abs(dy) > touchSlop && abs(dy) >= abs(dx)) {
                axis = Axis.VERTICAL
            } else if (abs(dx) > touchSlop && abs(dx) > abs(dy) * 1.5f) {
                axis = Axis.HORIZONTAL
            }
        }
        displacement = if (isHorizontal) dx else 0f
        if (isHorizontal) {
            val direction = if (displacement > 0) 1 else -1
            if (armedDirection == 0 && abs(displacement) >= actionDistance) {
                armedDirection = direction
            } else if (armedDirection != 0 && direction != armedDirection) {
                armedDirection = if (abs(displacement) >= actionDistance) direction else 0
            } else if (armedDirection != 0 && abs(displacement) < actionDistance * 0.8f) {
                armedDirection = 0
            }
        }
    }

    fun finish(x: Float, y: Float): ProfileSwipeAction? {
        move(x, y)
        val action = if (isArmed && abs(x - startX) > abs(y - startY) * 1.5f) {
            if (displacement > 0) ProfileSwipeAction.EDIT else ProfileSwipeAction.DELETE
        } else {
            null
        }
        cancel()
        return action
    }

    fun cancel() {
        axis = Axis.CANCELLED
        displacement = 0f
        armedDirection = 0
    }
}
