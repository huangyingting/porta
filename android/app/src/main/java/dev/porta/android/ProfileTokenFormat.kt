package dev.porta.android

internal object ProfileTokenFormat {
    const val VERSION = 2

    fun associatedData(profileId: String, server: String): ByteArray =
        "porta/profile-token/v2\n$profileId\n$server".toByteArray(Charsets.UTF_8)
}
