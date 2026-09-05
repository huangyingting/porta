package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidDeviceIdentityTest {
    @Test
    fun deviceNameTakesPrecedenceOverModelWithoutAddingASuffix() {
        assertEquals("My-Tablet", deviceIdentityFromNames(
            readDeviceName = { "My Tablet" },
            model = "Pixel Tablet",
            reportFallback = { error("A usable device name must not need a fallback") },
        ))
    }

    @Test
    fun normalizesNamesForTheServerWithoutHashingThem() {
        val examples = listOf(
            "DESKTOP-123" to "DESKTOP-123",
            "workstation.example" to "workstation.example",
            "My Tablet" to "My-Tablet",
            "  .._John's / Tablet_..  " to "John-s-Tablet",
            "Lab_PC-01" to "Lab_PC-01",
            "123" to "123",
            "Pad \uD83D\uDCF1" to "Pad",
            "\u5e73\u677f-01" to "01",
            "tablet\r\nInjected: header" to "tablet-Injected-header",
            "a".repeat(80) to "a".repeat(64),
        )
        for ((name, expected) in examples) {
            val actual = requireNotNull(deviceIdentityFromName(name))
            assertEquals(expected, actual)
            assertTrue(actual.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")))
            assertEquals(actual, deviceIdentityFromName(actual))
        }
    }

    @Test
    fun missingOrUnusableNamesUseTheModelAndReportTheFallback() {
        for (name in listOf(null, "", " \r\n ", ".._--", "\u5e73\u677f", "\u0000")) {
            assertNull(deviceIdentityFromName(name))
            val messages = mutableListOf<String>()
            assertEquals("Pixel-Tablet", deviceIdentityFromNames({ name }, "Pixel Tablet") { messages.add(it) })
            assertEquals(listOf("Device name missing or unsupported; using model name"), messages)
        }
    }

    @Test
    fun deniedLookupUsesTheModelWithoutLoggingTheExceptionContents() {
        val messages = mutableListOf<String>()
        val identity = deviceIdentityFromNames(
            { throw SecurityException("private exception details") }, "SM-X610",
        ) { messages.add(it) }
        assertEquals("SM-X610", identity)
        assertEquals(listOf("Device name access denied; using model name"), messages)
    }

    @Test
    fun unavailableNamesStillProduceAValidLabelWithAnExplicitWarning() {
        for (model in listOf(null, "", "unknown", "UNKNOWN", "\u5e73\u677f", ".._--")) {
            val messages = mutableListOf<String>()
            assertEquals("android", deviceIdentityFromNames({ null }, model) { messages.add(it) })
            assertEquals(listOf("Device name missing or unsupported and model name unavailable; using android"), messages)
        }
    }

    @Test
    fun everyNewConnectionReadsTheCurrentDeviceName() {
        var name = "Office Tablet"
        val lookup = { name }
        repeat(3) {
            assertEquals("Office-Tablet", deviceIdentityFromNames(lookup, "Pixel Tablet") { error(it) })
        }
        name = "Home Tablet"
        assertEquals("Home-Tablet", deviceIdentityFromNames(lookup, "Pixel Tablet") { error(it) })
    }

    @Test
    fun unexpectedLookupFailuresAreNotSilentlyHidden() {
        assertThrows(IllegalStateException::class.java) {
            deviceIdentityFromNames(
                { throw IllegalStateException("unexpected failure") }, "Pixel Tablet",
            ) { error("An unexpected failure must propagate") }
        }
    }
}
