package dev.porta.android

import java.util.UUID

internal data class ProfileSnapshot(
    val encoded: String?,
    val keyAlias: String,
    val selectedProfileId: String?,
)

internal data class ProfileStorageState(
    val current: ProfileSnapshot,
    val archives: List<ProfileSnapshot> = emptyList(),
)

internal data class ProfileReadResult(
    val profiles: List<VpnProfile>,
    val unreadableEntries: Int = 0,
    val unreadableDocument: Boolean = false,
) {
    val needsRecovery: Boolean get() = unreadableDocument || unreadableEntries > 0
}

internal interface ProfileStorage {
    fun read(): ProfileStorageState
    fun commit(state: ProfileStorageState): Boolean
}

internal interface ProfileCodec {
    fun decode(snapshot: ProfileSnapshot): ProfileReadResult
    fun encode(profiles: List<VpnProfile>, keyAlias: String): String
}

internal class ProfileRepository(
    private val storage: ProfileStorage,
    private val codec: ProfileCodec,
    private val newKeyAlias: () -> String = { "porta-profile-token-${UUID.randomUUID()}" },
) {
    fun read(): Pair<ProfileSnapshot, ProfileReadResult> = synchronized(lock) {
        val snapshot = storage.read().current
        snapshot to codec.decode(snapshot)
    }

    fun save(profile: VpnProfile): Boolean = update { stored ->
        stored.filterNot { it.id == profile.id }.map {
            if (profile.autoConnect) it.copy(autoConnect = false) else it
        }.plus(profile).sortedBy { it.name.lowercase() }
    }

    fun delete(profileId: String): Boolean = update { stored -> stored.filterNot { it.id == profileId } }

    private fun update(transform: (List<VpnProfile>) -> List<VpnProfile>): Boolean = synchronized(lock) {
        val before = storage.read()
        val decoded = codec.decode(before.current)
        if (decoded.needsRecovery) return false
        val profiles = transform(decoded.profiles)
        persist(before, before.copy(current = before.current.copy(
            encoded = codec.encode(profiles, before.current.keyAlias),
        )))
    }

    fun recover(expected: ProfileSnapshot): Boolean = synchronized(lock) {
        val before = storage.read()
        if (before.current != expected) return false
        val decoded = codec.decode(before.current)
        if (!decoded.needsRecovery) return false
        val alias = newKeyAlias()
        check(alias != before.current.keyAlias && before.archives.none { it.keyAlias == alias })
        val recovered = ProfileSnapshot(
            encoded = codec.encode(decoded.profiles, alias),
            keyAlias = alias,
            selectedProfileId = before.current.selectedProfileId?.takeIf { id ->
                decoded.profiles.any { it.id == id }
            },
        )
        // Preserve the exact ciphertext AND its key reference before switching storage.
        // Old keys are never deleted: a transient Keystore error may be recoverable.
        persist(before, ProfileStorageState(recovered, before.archives + before.current))
    }

    fun selectedProfileId(): String? = synchronized(lock) { storage.read().current.selectedProfileId }

    fun archiveCount(): Int = synchronized(lock) { storage.read().archives.size }

    fun restoreArchives(): Int = synchronized(lock) {
        val before = storage.read()
        val decoded = codec.decode(before.current)
        if (decoded.needsRecovery) return -1
        val restored = decoded.profiles.toMutableList()
        for (archive in before.archives) {
            for (profile in codec.decode(archive).profiles) {
                if (restored.none { it.id == profile.id }) {
                    restored += profile.copy(autoConnect = false)
                }
            }
        }
        val count = restored.size - decoded.profiles.size
        if (count == 0) return 0
        if (persist(before, before.copy(current = before.current.copy(
                encoded = codec.encode(restored.sortedBy { it.name.lowercase() }, before.current.keyAlias),
            )))
        ) count else -1
    }

    fun select(profileId: String?) = synchronized(lock) {
        val before = storage.read()
        persist(before, before.copy(current = before.current.copy(selectedProfileId = profileId)))
    }

    private fun persist(before: ProfileStorageState, after: ProfileStorageState): Boolean {
        if (storage.commit(after)) return true
        // SharedPreferences changes memory even when its disk commit fails.
        // Restore the active snapshot, but never throw away a recovery archive.
        storage.commit(before.copy(archives = after.archives))
        return false
    }

    companion object {
        private val lock = Any()
    }
}
