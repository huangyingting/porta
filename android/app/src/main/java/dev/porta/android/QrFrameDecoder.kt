package dev.porta.android

import com.google.zxing.BinaryBitmap
import com.google.zxing.ChecksumException
import com.google.zxing.DecodeHintType
import com.google.zxing.FormatException
import com.google.zxing.LuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.nio.ByteBuffer

internal class QrFrameDecoder {
    private val reader = QRCodeReader()
    private val hints = mapOf(DecodeHintType.CHARACTER_SET to "UTF-8")

    fun decode(frame: QrLuminanceFrame): String? {
        val source = PlanarYUVLuminanceSource(
            frame.bytes, frame.width, frame.height, 0, 0, frame.width, frame.height, false,
        )
        return decode(source) ?: decode(source.invert())
    }

    private fun decode(source: LuminanceSource): String? = try {
        reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (_: NotFoundException) {
        null
    } catch (_: ChecksumException) {
        null
    } catch (_: FormatException) {
        null
    } finally {
        reader.reset()
    }
}

internal class QrLuminanceFrame(val bytes: ByteArray, val width: Int, val height: Int) {
    companion object {
        fun fromPlane(
            buffer: ByteBuffer,
            imageWidth: Int,
            imageHeight: Int,
            rowStride: Int,
            pixelStride: Int,
            cropLeft: Int,
            cropTop: Int,
            cropWidth: Int,
            cropHeight: Int,
            rotationDegrees: Int,
        ): QrLuminanceFrame? {
            if (imageWidth <= 0 || imageHeight <= 0 || rowStride <= 0 || pixelStride <= 0 ||
                cropLeft < 0 || cropTop < 0 || cropWidth <= 0 || cropHeight <= 0 ||
                cropLeft.toLong() + cropWidth > imageWidth ||
                cropTop.toLong() + cropHeight > imageHeight ||
                cropWidth.toLong() * cropHeight > 4_194_304 ||
                rotationDegrees !in setOf(0, 90, 180, 270) ||
                rowStride.toLong() < (imageWidth - 1L) * pixelStride + 1
            ) return null
            val lastIndex = (cropTop + cropHeight - 1L) * rowStride +
                (cropLeft + cropWidth - 1L) * pixelStride
            if (lastIndex >= buffer.remaining()) return null
            val rotated = rotationDegrees == 90 || rotationDegrees == 270
            val width = if (rotated) cropHeight else cropWidth
            val height = if (rotated) cropWidth else cropHeight
            val bytes = ByteArray(width * height)
            val base = buffer.position()
            for (y in 0 until cropHeight) {
                for (x in 0 until cropWidth) {
                    val destination = when (rotationDegrees) {
                        90 -> x * width + cropHeight - 1 - y
                        180 -> (cropHeight - 1 - y) * width + cropWidth - 1 - x
                        270 -> (cropWidth - 1 - x) * width + y
                        else -> y * width + x
                    }
                    // Absolute reads preserve the camera-owned buffer's position.
                    bytes[destination] = buffer.get(
                        base + (cropTop + y) * rowStride + (cropLeft + x) * pixelStride,
                    )
                }
            }
            return QrLuminanceFrame(bytes, width, height)
        }
    }
}
