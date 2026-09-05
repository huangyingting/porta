package dev.porta.android

import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.InputStream
import java.util.Base64
import java.util.Properties

class ProfileQrInteropTest {
    @Test
    fun decodesTheActualGoServerPngAndImportsExactlyItsProfile() {
        val fixture = Properties().apply {
            checkNotNull(ProfileQrInteropTest::class.java.getResourceAsStream("/profile-qr.properties")).use { load(it) }
        }
        val png = Base64.getDecoder().decode(fixture.getProperty("png"))
        // Android's Kotlin compile classpath omits java.desktop; the JDK test runtime supplies it.
        val image = Class.forName("javax.imageio.ImageIO").getMethod("read", InputStream::class.java)
            .invoke(null, png.inputStream())
        val imageType = Class.forName("java.awt.image.BufferedImage")
        val width = imageType.getMethod("getWidth").invoke(image) as Int
        val height = imageType.getMethod("getHeight").invoke(image) as Int
        val intType = Int::class.javaPrimitiveType
        val pixels = imageType.getMethod(
            "getRGB", intType, intType, intType, intType, IntArray::class.java, intType, intType,
        ).invoke(image, 0, 0, width, height, null, 0, width) as IntArray
        val text = QRCodeReader().decode(BinaryBitmap(HybridBinarizer(
            RGBLuminanceSource(width, height, pixels),
        ))).text
        assertEquals(fixture.getProperty("uri"), text)
        val profile = checkNotNull(ProfileQr.parse(text))
        assertEquals(fixture.getProperty("server"), profile.server)
        assertEquals(fixture.getProperty("token"), profile.token)
        assertEquals(fixture.getProperty("name"), profile.name)
    }
}
