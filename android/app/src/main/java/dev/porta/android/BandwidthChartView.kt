package dev.porta.android

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.view.View
import java.util.Locale
import kotlin.math.max

internal class BandwidthChartView(context: Context) : View(context) {
    private val downloadSamples = ArrayDeque<Long>()
    private val uploadSamples = ArrayDeque<Long>()
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.rgb(43, 61, 82)
        strokeWidth = dp(1f)
    }
    private val downloadPaint = linePaint(Color.rgb(110, 231, 183))
    private val uploadPaint = linePaint(Color.rgb(96, 165, 250))

    fun addSample(downloadBytesPerSecond: Long, uploadBytesPerSecond: Long) {
        append(downloadSamples, downloadBytesPerSecond)
        append(uploadSamples, uploadBytesPerSecond)
        invalidate()
    }

    fun reset() {
        downloadSamples.clear()
        uploadSamples.clear()
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val chartWidth = width.toFloat()
        val chartHeight = height.toFloat()
        if (chartWidth <= 0f || chartHeight <= 0f) return

        for (line in 1..3) {
            val y = chartHeight * line / 4f
            canvas.drawLine(0f, y, chartWidth, y, gridPaint)
        }
        drawSeries(canvas, downloadSamples, downloadPaint, chartWidth, chartHeight)
        drawSeries(canvas, uploadSamples, uploadPaint, chartWidth, chartHeight)
    }

    private fun drawSeries(
        canvas: Canvas,
        samples: ArrayDeque<Long>,
        paint: Paint,
        chartWidth: Float,
        chartHeight: Float,
    ) {
        if (samples.isEmpty()) return
        val ceiling = max(
            MINIMUM_SCALE,
            max(
                downloadSamples.maxOrNull() ?: 0L,
                uploadSamples.maxOrNull() ?: 0L,
            ),
        )
        val values = samples.toList()
        val startIndex = MAX_SAMPLES - values.size
        val path = Path()
        values.forEachIndexed { index, value ->
            val x = chartWidth * (startIndex + index) / (MAX_SAMPLES - 1)
            val y = chartHeight - chartHeight * value.coerceAtMost(ceiling).toFloat() / ceiling.toFloat()
            if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        canvas.drawPath(path, paint)
    }

    private fun append(samples: ArrayDeque<Long>, value: Long) {
        if (samples.size == MAX_SAMPLES) samples.removeFirst()
        samples.addLast(value.coerceAtLeast(0L))
    }

    private fun linePaint(colorValue: Int) = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = colorValue
        strokeWidth = dp(2f)
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }

    private fun dp(value: Float): Float = value * resources.displayMetrics.density

    companion object {
        private const val MAX_SAMPLES = 60
        private const val MINIMUM_SCALE = 1024L
    }
}

internal fun formatDataRate(bytesPerSecond: Long): String {
    val value = bytesPerSecond.coerceAtLeast(0L).toDouble()
    return when {
        value >= 1024.0 * 1024.0 -> String.format(Locale.US, "%.1f MB/s", value / (1024.0 * 1024.0))
        value >= 1024.0 -> String.format(Locale.US, "%.1f KB/s", value / 1024.0)
        else -> "${value.toLong()} B/s"
    }
}

internal fun formatDataSize(bytes: Long): String {
    val value = bytes.coerceAtLeast(0L).toDouble()
    return when {
        value >= 1024.0 * 1024.0 * 1024.0 ->
            String.format(Locale.US, "%.2f GB", value / (1024.0 * 1024.0 * 1024.0))
        value >= 1024.0 * 1024.0 -> String.format(Locale.US, "%.1f MB", value / (1024.0 * 1024.0))
        value >= 1024.0 -> String.format(Locale.US, "%.1f KB", value / 1024.0)
        else -> "${value.toLong()} B"
    }
}
