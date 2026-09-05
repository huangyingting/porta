package dev.porta.android

import org.junit.Assert.assertThrows
import org.junit.Test
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class ProfileTokenFormatTest {
    private val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
    private val nonce = ByteArray(12) { (it + 10).toByte() }

    @Test
    fun profileAndServerBindingsCannotBeChanged() {
        val binding = ProfileTokenFormat.associatedData("profile-id", "https://example.com")
        val ciphertext = crypt(Cipher.ENCRYPT_MODE, "token".toByteArray(), binding)
        for (changed in listOf(
            ProfileTokenFormat.associatedData("other-profile", "https://example.com"),
            ProfileTokenFormat.associatedData("profile-id", "https://other.example.com"),
        )) {
            assertThrows(AEADBadTagException::class.java) { crypt(Cipher.DECRYPT_MODE, ciphertext, changed) }
        }
    }

    private fun crypt(mode: Int, value: ByteArray, binding: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(mode, key, GCMParameterSpec(128, nonce))
            updateAAD(binding)
            doFinal(value)
        }
}
