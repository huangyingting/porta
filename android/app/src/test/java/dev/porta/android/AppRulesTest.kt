package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRulesTest {
    private val own = "dev.porta.android"

    @Test
    fun modesNeverMixAllowedAndDisallowedApps() {
        assertEquals(AppRules(emptyList(), listOf(own)), appRules(AppMode.ALL, listOf("com.example.mail"), own))
        assertEquals(
            AppRules(listOf("com.example.mail", "org.example.chat"), emptyList()),
            appRules(AppMode.ONLY, listOf(" com.example.mail", "org.example.chat", "com.example.mail", own, ""), own),
        )
        assertEquals(
            AppRules(emptyList(), listOf(own, "com.example.bank")),
            appRules(AppMode.EXCEPT, listOf("com.example.bank", own), own),
        )
        for (mode in AppMode.entries) {
            val rules = appRules(mode, listOf("com.example.mail"), own)
            assertTrue(rules.allowed.isEmpty() || rules.disallowed.isEmpty())
        }
    }

    @Test
    fun modeCodesAndPackageNamesAreStrict() {
        assertEquals(AppMode.ONLY, AppMode.fromCode("only"))
        assertEquals(AppMode.ALL, AppMode.fromCode("nonsense"))
        assertEquals(AppMode.ALL, AppMode.fromCode(null))
        assertTrue(isPackageName("com.example.mail"))
        assertTrue(isPackageName("org.example.chat_2"))
        for (invalid in listOf("", "mail", "com..mail", "1com.example", "com.example.mail;rm", "com.exa mple")) {
            assertFalse(invalid, isPackageName(invalid))
        }
    }
}
