package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AccountStatusTest {
    @Test
    fun parsesBridgeEncodingAndIgnoresMalformedFields() {
        assertEquals(AccountLimits(), parseAccountLimits("|||"))
        assertFalse(parseAccountLimits("|||").isLimited)
        assertEquals(AccountLimits(), parseAccountLimits("garbage"))
        val limits = parseAccountLimits("1931385599|2147483648|536870912|5000")
        assertEquals(1_931_385_599L, limits.expiresAtSeconds)
        assertEquals(2_147_483_648L, limits.quotaBytes)
        assertEquals(536_870_912L, limits.quotaUsedBytes)
        assertEquals(5_000, limits.rateLimitKbps)
        assertTrue(limits.isLimited)
        assertNull(parseAccountLimits("x|0|-1|0").quotaBytes)
    }

    @Test
    fun warnsNearExpiryAndQuotaExhaustion() {
        val now = 1_900_000_000_000L
        assertTrue(AccountLimits(expiresAtSeconds = now / 1_000 + 3 * 86_400).expiresSoon(now))
        assertFalse(AccountLimits(expiresAtSeconds = now / 1_000 + 30 * 86_400).expiresSoon(now))
        assertTrue(AccountLimits(quotaBytes = 1_000, quotaUsedBytes = 950).quotaNearlyUsed())
        assertFalse(AccountLimits(quotaBytes = 1_000, quotaUsedBytes = 500).quotaNearlyUsed())
        assertFalse(AccountLimits(quotaBytes = 1_000).quotaNearlyUsed())
    }

    @Test
    fun detectsDenialCodesInNativeFailureMessages() {
        assertEquals(
            AccountDenial.EXPIRED,
            accountDenialIn(
                "Connection rejected: Rust error: account-denied:account-expired: the gateway account has expired",
            ),
        )
        assertEquals(
            AccountDenial.QUOTA_EXCEEDED,
            accountDenialIn("account-denied:quota-exceeded: monthly data quota"),
        )
        assertEquals(
            AccountDenial.DEVICE_PENDING,
            accountDenialIn("Connection rejected: account-denied:device-pending: waiting for approval"),
        )
        assertNull(accountDenialIn("gateway returned HTTP 401 Unauthorized"))
    }
}
