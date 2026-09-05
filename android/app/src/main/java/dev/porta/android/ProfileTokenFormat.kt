package dev.porta.android

internal object ProfileTokenFormat {
    const val VERSION = 2

    fun associatedData(
        profileId: String,
        server: String,
        version: Int = VERSION,
        previousClientId: String? = null,
    ): ByteArray = when (version) {
        1 -> "$profileId\n$server\n${requireNotNull(previousClientId)}"
        VERSION -> "porta/profile-token/v2\n$profileId\n$server"
        else -> throw IllegalArgumentException("Unsupported profile storage version")
    }.toByteArray(Charsets.UTF_8)
}
