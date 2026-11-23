package dev.porta.android

/** Account limits the gateway reported when the tunnel was established. */
internal data class AccountLimits(
    val expiresAtSeconds: Long? = null,
    val quotaBytes: Long? = null,
    /** Usage snapshot taken at connection time; null until the gateway counts it. */
    val quotaUsedBytes: Long? = null,
    val rateLimitKbps: Int? = null,
) {
    val isLimited: Boolean
        get() = expiresAtSeconds != null || quotaBytes != null || rateLimitKbps != null

    fun expiresSoon(nowMillis: Long): Boolean =
        expiresAtSeconds?.let { it * 1_000L - nowMillis < EXPIRY_WARNING_MILLIS } ?: false

    fun quotaNearlyUsed(): Boolean {
        val quota = quotaBytes ?: return false
        val used = quotaUsedBytes ?: return false
        return used >= quota * 9 / 10
    }

    private companion object {
        const val EXPIRY_WARNING_MILLIS = 7L * 24 * 60 * 60 * 1_000
    }
}

/** Parses the native bridge's `expires|quota|used|rate` encoding. */
internal fun parseAccountLimits(value: String): AccountLimits {
    val fields = value.split('|')
    if (fields.size != 4) return AccountLimits()
    return AccountLimits(
        expiresAtSeconds = fields[0].toLongOrNull(),
        quotaBytes = fields[1].toLongOrNull()?.takeIf { it > 0 },
        quotaUsedBytes = fields[2].toLongOrNull()?.takeIf { it >= 0 },
        rateLimitKbps = fields[3].toIntOrNull()?.takeIf { it > 0 },
    )
}

/** A gateway refusal caused by an account limit rather than a fault. */
internal enum class AccountDenial(val code: String) {
    EXPIRED("account-expired"),
    QUOTA_EXCEEDED("quota-exceeded"),
}

/** Finds the stable denial code the native bridge places in failure messages. */
internal fun accountDenialIn(message: String): AccountDenial? =
    AccountDenial.entries.firstOrNull { "account-denied:${it.code}" in message }
