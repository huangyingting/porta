package dev.porta.android

/** Which apps a profile's tunnel carries. */
internal enum class AppMode(val code: String) {
    /** Every app except Porta itself. */
    ALL("all"),

    /** Only the selected apps. */
    ONLY("only"),

    /** Every app except the selected ones and Porta. */
    EXCEPT("except"),
    ;

    companion object {
        fun fromCode(code: String?): AppMode = entries.firstOrNull { it.code == code } ?: ALL
    }
}

/** At most this many apps per profile. */
internal const val MAX_PROFILE_APPS = 256

/**
 * The VpnService application lists for [mode]. Android rejects a builder
 * with both allowed and disallowed applications, so [AppMode.ONLY] lists
 * only the selected apps; Porta, which is not among them, stays outside the
 * tunnel as it must. Otherwise Porta is always disallowed.
 */
internal data class AppRules(val allowed: List<String>, val disallowed: List<String>)

internal fun appRules(mode: AppMode, apps: List<String>, ownPackage: String): AppRules {
    val selected = apps.map(String::trim).filter { it.isNotEmpty() && it != ownPackage }.distinct()
    return when (mode) {
        AppMode.ALL -> AppRules(emptyList(), listOf(ownPackage))
        AppMode.ONLY -> AppRules(selected, emptyList())
        AppMode.EXCEPT -> AppRules(emptyList(), listOf(ownPackage) + selected)
    }
}

/** Whether [value] looks like an Android package name. */
internal fun isPackageName(value: String): Boolean =
    value.length in 1..255 && value.split('.').let { parts ->
        parts.size >= 2 && parts.all { part ->
            part.isNotEmpty() && part.first().isLetter() && part.all { it.isLetterOrDigit() || it == '_' }
        }
    }
