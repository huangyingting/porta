package dev.porta.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
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
    fun oldTokensCanBeAuthenticatedAndReencryptedWithoutKeepingADeviceId() {
        val oldBinding = "profile-id\nhttps://example.com\nold-editable-device".toByteArray()
        val token = "example-client-token".toByteArray()
        val oldCiphertext = crypt(Cipher.ENCRYPT_MODE, token, oldBinding)
        assertThrows(AEADBadTagException::class.java) {
            crypt(
                Cipher.DECRYPT_MODE,
                oldCiphertext,
                ProfileTokenFormat.associatedData("profile-id", "https://example.com", 1, "changed-device-id"),
            )
        }
        val restored = crypt(
            Cipher.DECRYPT_MODE,
            oldCiphertext,
            ProfileTokenFormat.associatedData("profile-id", "https://example.com", 1, "old-editable-device"),
        )
        assertArrayEquals(token, restored)
        val binding = ProfileTokenFormat.associatedData("profile-id", "https://example.com")
        assertFalse(binding.toString(Charsets.UTF_8).contains("old-editable-device"))
        val rewritten = crypt(Cipher.ENCRYPT_MODE, restored, binding)
        assertArrayEquals(token, crypt(Cipher.DECRYPT_MODE, rewritten, binding))
        assertNotEquals(oldCiphertext.toList(), rewritten.toList())
    }

    @Test
    fun profileAndServerBindingsCannotBeChangedOrDowngraded() {
        val binding = ProfileTokenFormat.associatedData("profile-id", "https://example.com")
        val ciphertext = crypt(Cipher.ENCRYPT_MODE, "token".toByteArray(), binding)
        for (changed in listOf(
            ProfileTokenFormat.associatedData("other-profile", "https://example.com"),
            ProfileTokenFormat.associatedData("profile-id", "https://other.example.com"),
            ProfileTokenFormat.associatedData("profile-id", "https://example.com", 1, "device"),
        )) {
            assertThrows(AEADBadTagException::class.java) { crypt(Cipher.DECRYPT_MODE, ciphertext, changed) }
        }
    }

    @Test
    fun unknownFormatsAndIncompleteOldBindingsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            ProfileTokenFormat.associatedData("profile", "https://example.com", 3)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProfileTokenFormat.associatedData("profile", "https://example.com", 1)
        }
    }

    private fun crypt(mode: Int, value: ByteArray, binding: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(mode, key, GCMParameterSpec(128, nonce))
            updateAAD(binding)
            doFinal(value)
        }
}
