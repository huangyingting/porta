package dev.porta.android

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.ByteBuffer

class QrFrameDecoderTest {
    @Test
    fun handlesPaddedRowsPixelStrideCropAndBufferOffset() {
        val bytes = ByteArray(50) { 99 }
        for (y in 0..2) for (x in 0..3) bytes[3 + y * 12 + x * 2] = (y * 4 + x).toByte()
        val buffer = ByteBuffer.wrap(bytes).apply { position(3); limit(34) }
        val frame = QrLuminanceFrame.fromPlane(buffer, 4, 3, 12, 2, 1, 1, 2, 2, 0)!!
        assertArrayEquals(byteArrayOf(5, 6, 9, 10), frame.bytes)
        assertEquals(2, frame.width)
        assertEquals(2, frame.height)
        assertEquals(3, buffer.position())
        assertEquals(34, buffer.limit())
    }

    @Test
    fun rotatesRectangularFramesClockwiseWithoutLosingPixels() {
        val expected = mapOf(
            0 to byteArrayOf(1, 2, 3, 4, 5, 6),
            90 to byteArrayOf(4, 1, 5, 2, 6, 3),
            180 to byteArrayOf(6, 5, 4, 3, 2, 1),
            270 to byteArrayOf(3, 6, 2, 5, 1, 4),
        )
        for ((rotation, bytes) in expected) {
            val frame = QrLuminanceFrame.fromPlane(
                ByteBuffer.wrap(byteArrayOf(1, 2, 3, 4, 5, 6)),
                3, 2, 3, 1, 0, 0, 3, 2, rotation,
            )!!
            assertArrayEquals(bytes, frame.bytes)
            assertEquals(if (rotation % 180 == 0) 3 else 2, frame.width)
            assertEquals(if (rotation % 180 == 0) 2 else 3, frame.height)
        }
    }

    @Test
    fun rejectsTruncatedInvalidOrUnboundedFrames() {
        fun frame(
            size: Int = 12,
            row: Int = 4,
            pixel: Int = 1,
            left: Int = 0,
            top: Int = 0,
            width: Int = 4,
            height: Int = 3,
            rotation: Int = 0,
        ) = QrLuminanceFrame.fromPlane(
            ByteBuffer.allocate(size), 4, 3, row, pixel, left, top, width, height, rotation,
        )
        assertNull(frame(size = 11))
        assertNull(frame(size = 0))
        assertNull(frame(row = 0))
        assertNull(frame(row = 3))
        assertNull(frame(pixel = 0))
        assertNull(frame(pixel = 2))
        assertNull(frame(left = -1))
        assertNull(frame(top = -1))
        assertNull(frame(left = 1))
        assertNull(frame(top = 1))
        assertNull(frame(width = 0))
        assertNull(frame(height = 0))
        assertNull(frame(rotation = 45))
        assertNull(frame(width = Int.MAX_VALUE))
        assertNull(frame(row = Int.MAX_VALUE))
        assertNull(QrLuminanceFrame.fromPlane(
            ByteBuffer.allocate(1), 4096, 4096, 4096, 1, 0, 0, 4096, 4096, 0,
        ))
    }

    @Test
    fun supportsReadOnlyAndDirectBuffersWithoutRequiringBackingArray() {
        val buffer = ByteBuffer.allocateDirect(6).put(byteArrayOf(1, 2, 3, 4, 5, 6))
            .apply { flip() }.asReadOnlyBuffer()
        val frame = QrLuminanceFrame.fromPlane(buffer, 3, 2, 3, 1, 0, 0, 3, 2, 90)!!
        assertArrayEquals(byteArrayOf(4, 1, 5, 2, 6, 3), frame.bytes)
    }

    @Test
    fun decodesQrAtEveryRotationWithCameraStrideAndCrop() {
        val text = "porta://profile?v=1&server=https%3A%2F%2Fexample.com&token=example"
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 320, 320)
        val width = 350
        val height = 340
        val rowStride = width * 2 + 13
        val bytes = ByteArray(rowStride * height) { 0xff.toByte() }
        for (y in 0 until matrix.height) for (x in 0 until matrix.width) {
            bytes[(y + 10) * rowStride + (x + 15) * 2] = if (matrix[x, y]) 0 else 0xff.toByte()
        }
        val decoder = QrFrameDecoder()
        for (rotation in listOf(0, 90, 180, 270)) {
            val frame = QrLuminanceFrame.fromPlane(
                ByteBuffer.wrap(bytes), width, height, rowStride, 2, 15, 10, 320, 320, rotation,
            )!!
            assertEquals(text, decoder.decode(frame))
        }
    }

    @Test
    fun decodesInvertedQrAndCanReuseDecoderAfterNoCode() {
        val decoder = QrFrameDecoder()
        assertNull(decoder.decode(QrLuminanceFrame(ByteArray(320 * 320) { -1 }, 320, 320)))
        val text = "porta://profile?v=1&server=https%3A%2F%2Fexample.com&token=example"
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 320, 320)
        val bytes = ByteArray(320 * 320) { index -> if (matrix[index % 320, index / 320]) -1 else 0 }
        assertEquals(text, decoder.decode(QrLuminanceFrame(bytes, 320, 320)))
    }

    @Test
    fun decodedUntrustedTextStillMustPassProfileValidation() {
        val text = "https://example.com/not-a-profile"
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 240, 240,
            mapOf(EncodeHintType.CHARACTER_SET to "UTF-8"))
        val bytes = ByteArray(240 * 240) { index -> if (matrix[index % 240, index / 240]) 0 else -1 }
        val decoded = QrFrameDecoder().decode(QrLuminanceFrame(bytes, 240, 240))
        assertEquals(text, decoded)
        assertNull(ProfileQr.parse(decoded))
    }
}
