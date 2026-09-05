package dev.porta.android

import android.content.Context
import android.graphics.Rect
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.HapticFeedbackConstants
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.widget.FrameLayout
import android.widget.TextView

internal class SwipeProfileLayout(
    context: Context,
    private val card: View,
    private val controls: List<View>,
    private val canSwipe: () -> Boolean,
    private val onAction: (ProfileSwipeAction) -> Unit,
    editColor: Int,
    deleteColor: Int,
    textColor: Int,
) : FrameLayout(context) {
    private val touchSlop = ViewConfiguration.get(context).scaledTouchSlop.toFloat()
    private var gesture = ProfileSwipeGesture(touchSlop, dp(72).toFloat())
    private var blocked = false
    private var armed = false
    private val editLabel = actionLabel(R.string.edit, Gravity.LEFT, editColor, textColor)
    private val deleteLabel = actionLabel(R.string.delete, Gravity.RIGHT, deleteColor, textColor)

    init {
        addView(editLabel, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        addView(deleteLabel, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        addView(card, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT))
        isClickable = true
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    override fun onInterceptTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> begin(event)
            MotionEvent.ACTION_MOVE -> {
                if (blocked || !canSwipe()) return false
                gesture.move(event.x, event.y)
                if (gesture.isHorizontal) {
                    parent?.requestDisallowInterceptTouchEvent(true)
                    return true
                }
            }
            MotionEvent.ACTION_POINTER_DOWN, MotionEvent.ACTION_CANCEL -> cancelGesture()
        }
        return false
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (blocked) return false
        if (event.pointerCount != 1 || !canSwipe()) {
            cancelGesture()
            return true
        }
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> return true
            MotionEvent.ACTION_MOVE -> {
                gesture.move(event.x, event.y)
                if (gesture.isHorizontal) {
                    parent?.requestDisallowInterceptTouchEvent(true)
                    showDrag()
                }
            }
            MotionEvent.ACTION_UP -> {
                val tap = gesture.isTap
                val action = gesture.finish(event.x, event.y)
                resetCard()
                if (action != null) onAction(action) else if (tap) performClick()
            }
            MotionEvent.ACTION_POINTER_DOWN, MotionEvent.ACTION_CANCEL -> cancelGesture()
        }
        return true
    }

    override fun performClick(): Boolean = super.performClick()

    override fun onDetachedFromWindow() {
        gesture.cancel()
        card.animate().cancel()
        card.translationX = 0f
        parent?.requestDisallowInterceptTouchEvent(false)
        super.onDetachedFromWindow()
    }

    private fun begin(event: MotionEvent) {
        card.animate().cancel()
        card.translationX = 0f
        editLabel.visibility = INVISIBLE
        deleteLabel.visibility = INVISIBLE
        blocked = !canSwipe() || event.pointerCount != 1 || controls.any { control ->
            val bounds = Rect(0, 0, control.width, control.height)
            offsetDescendantRectToMyCoords(control, bounds)
            control.isShown && bounds.contains(event.x.toInt(), event.y.toInt())
        }
        armed = false
        gesture = ProfileSwipeGesture(touchSlop, maxOf(dp(72).toFloat(), width * 0.28f))
        if (!blocked) gesture.begin(event.x, event.y)
    }

    private fun showDrag() {
        val distance = gesture.displacement
        card.translationX = distance.coerceIn(-width * 0.42f, width * 0.42f)
        editLabel.visibility = if (distance > 0) VISIBLE else INVISIBLE
        deleteLabel.visibility = if (distance < 0) VISIBLE else INVISIBLE
        editLabel.alpha = if (gesture.isArmed) 1f else 0.65f
        deleteLabel.alpha = if (gesture.isArmed) 1f else 0.65f
        if (gesture.isArmed && !armed) {
            performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP)
        }
        armed = gesture.isArmed
    }

    private fun cancelGesture() {
        gesture.cancel()
        resetCard()
    }

    private fun resetCard() {
        parent?.requestDisallowInterceptTouchEvent(false)
        card.animate().translationX(0f).setDuration(160).withEndAction {
            editLabel.visibility = INVISIBLE
            deleteLabel.visibility = INVISIBLE
        }.start()
        armed = false
    }

    private fun actionLabel(label: Int, edge: Int, fill: Int, color: Int) = TextView(context).apply {
        setText(label)
        gravity = Gravity.CENTER_VERTICAL or edge
        textSize = 14f
        setTextColor(color)
        setTypeface(typeface, Typeface.BOLD)
        setPadding(dp(20), 0, dp(20), 0)
        background = GradientDrawable().apply {
            cornerRadius = dp(18).toFloat()
            setColor(fill)
        }
        visibility = INVISIBLE
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
