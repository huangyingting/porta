package dev.porta.android

import kotlin.math.abs

internal enum class ProfileSwipeAction { EDIT, DELETE }

internal class ProfileSwipeGesture(
    private val touchSlop: Float,
    private val actionDistance: Float,
) {
    private enum class Axis { PENDING, HORIZONTAL, VERTICAL, CANCELLED }

    private var axis = Axis.CANCELLED
    private var startX = 0f
    private var startY = 0f
    private var moved = false
    var displacement = 0f
        private set
    val isHorizontal: Boolean get() = axis == Axis.HORIZONTAL
    val isTap: Boolean get() = axis == Axis.PENDING && !moved
    val isArmed: Boolean get() = isHorizontal && abs(displacement) >= actionDistance

    init {
        require(touchSlop > 0 && actionDistance > touchSlop)
    }

    fun begin(x: Float, y: Float) {
        startX = x
        startY = y
        displacement = 0f
        moved = false
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
    }
}
