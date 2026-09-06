package dev.porta.android

import org.junit.Assert.*
import org.junit.Test
import java.security.GeneralSecurityException

class ProfileStorageTest {
    private val healthy = VpnProfile("healthy", "Healthy", "https://vpn.example", "secret", true)
    private val damaged = healthy.copy(id = "damaged", name = "Damaged")
    private val added = healthy.copy(id = "new", name = "New", autoConnect = false)

    private class MemoryStorage(var state: ProfileStorageState) : ProfileStorage {
        var commits = 0
        var failCommits = false
        override fun read() = state
        override fun commit(state: ProfileStorageState): Boolean {
            commits++
            this.state = state // SharedPreferences also mutates memory on a failed commit.
            return !failCommits
        }
    }

    private class FakeCodec : ProfileCodec {
        val documents = mutableMapOf<String, ProfileReadResult>()
        val keys = mutableMapOf<String, String>()
        var encryptions = 0
        var failEncrypt = false
        override fun decode(snapshot: ProfileSnapshot): ProfileReadResult =
            snapshot.encoded?.let { documents.getValue(it) } ?: ProfileReadResult(emptyList())

        override fun encode(profiles: List<VpnProfile>, keyAlias: String): String {
            if (failEncrypt) throw GeneralSecurityException("injected Keystore failure")
            val encoded = "encrypted-${++encryptions}"
            documents[encoded] = ProfileReadResult(profiles)
            keys[encoded] = keyAlias
            return encoded
        }
    }

    private class Fixture(val storage: MemoryStorage, val codec: FakeCodec) {
        var keyNumber = 0
        val repository = ProfileRepository(storage, codec) { "new-key-${++keyNumber}" }
    }

    private fun fixture(unreadableDocument: Boolean = false): Fixture {
        val snapshot = ProfileSnapshot("original ciphertext", "original-key", healthy.id)
        val codec = FakeCodec().apply {
            documents[snapshot.encoded!!] = if (unreadableDocument) {
                ProfileReadResult(emptyList(), unreadableDocument = true)
            } else ProfileReadResult(listOf(healthy), unreadableEntries = 1)
        }
        return Fixture(MemoryStorage(ProfileStorageState(snapshot)), codec)
    }

    @Test fun oneUnreadableEntryDoesNotDestroyHealthyProfilesOnSaveOrDelete() {
        val f = fixture()
        val original = f.storage.state
        assertEquals(listOf(healthy), f.repository.read().second.profiles)
        assertFalse(f.repository.save(added))
        assertFalse(f.repository.delete(healthy.id))
        assertEquals(original, f.storage.state)
        assertEquals(0, f.storage.commits)
        assertEquals(0, f.codec.encryptions)
        assertEquals(0, f.keyNumber)
    }

    @Test fun malformedDocumentIsNotReplacedByOrdinarySave() {
        val f = fixture(unreadableDocument = true)
        val original = f.storage.state
        assertTrue(f.repository.read().second.unreadableDocument)
        assertFalse(f.repository.save(added))
        assertEquals(original, f.storage.state)
        assertEquals(0, f.storage.commits)
    }

    @Test fun explicitRecoveryRetainsHealthyProfilesCiphertextSelectionAndOldKeyReference() {
        val f = fixture()
        val original = f.storage.state.current
        assertTrue(f.repository.recover(original))
        assertEquals(listOf(healthy), f.repository.read().second.profiles)
        assertFalse(f.repository.read().second.needsRecovery)
        assertEquals(healthy.id, f.repository.selectedProfileId())
        assertEquals(listOf(original), f.storage.state.archives)
        assertEquals("new-key-1", f.storage.state.current.keyAlias)
        assertEquals("new-key-1", f.codec.keys[f.storage.state.current.encoded])
        assertTrue(f.repository.save(added))
        assertEquals(2, f.repository.read().second.profiles.size)
        assertEquals(listOf(original), f.storage.state.archives)
    }

    @Test fun recoveryClearsOnlyAnUnreadableSelection() {
        val f = fixture()
        f.repository.select(damaged.id)
        assertTrue(f.repository.recover(f.storage.state.current))
        assertNull(f.repository.selectedProfileId())
        assertEquals(damaged.id, f.storage.state.archives.single().selectedProfileId)
    }

    @Test fun recoveryOfMalformedDocumentArchivesOriginalBeforeStartingEmpty() {
        val f = fixture(unreadableDocument = true)
        val original = f.storage.state.current
        assertTrue(f.repository.recover(original))
        assertEquals(listOf(original), f.storage.state.archives)
        assertTrue(f.repository.read().second.profiles.isEmpty())
        assertTrue(f.repository.save(added))
    }

    @Test fun encryptionFailureDoesNotChangeOriginalStorage() {
        val f = fixture()
        val original = f.storage.state
        f.codec.failEncrypt = true
        try {
            f.repository.recover(original.current)
            fail("expected encryption failure")
        } catch (_: GeneralSecurityException) {
            assertEquals(original, f.storage.state)
            assertEquals(0, f.storage.commits)
        }
    }

    @Test fun failedDiskCommitRestoresActiveMemoryAndRetainsRecoveryArchive() {
        val f = fixture()
        val original = f.storage.state.current
        f.storage.failCommits = true
        assertFalse(f.repository.recover(original))
        assertEquals(original, f.storage.state.current)
        assertEquals(listOf(original), f.storage.state.archives)
        assertTrue(f.repository.read().second.needsRecovery)
        f.storage.failCommits = false
        assertTrue(f.repository.recover(original))
        assertEquals(listOf(healthy), f.repository.read().second.profiles)
    }

    @Test fun staleConsentCannotArchiveChangedStorage() {
        val f = fixture()
        val original = f.storage.state.current
        f.repository.select(damaged.id)
        val beforeRecovery = f.storage.state
        assertFalse(f.repository.recover(original))
        assertEquals(beforeRecovery, f.storage.state)
        assertTrue(f.storage.state.archives.isEmpty())
    }

    @Test fun retryAfterTransientReadFailureDoesNotRequireRecovery() {
        val f = fixture()
        val original = f.storage.state.current
        f.codec.documents[original.encoded!!] = ProfileReadResult(listOf(healthy, damaged))
        assertFalse(f.repository.read().second.needsRecovery)
        assertFalse(f.repository.recover(original))
        assertEquals(0, f.storage.commits)
        assertTrue(f.repository.save(added))
        assertEquals(3, f.repository.read().second.profiles.size)
    }

    @Test fun archivedProfilesCanBeRetriedWithoutReplacingEditsOrEnablingAutoConnect() {
        val f = fixture()
        val original = f.storage.state.current
        assertTrue(f.repository.recover(original))
        val edited = healthy.copy(name = "Edited", token = "replacement")
        assertTrue(f.repository.save(edited))
        f.codec.documents[original.encoded!!] = ProfileReadResult(listOf(healthy, damaged))
        assertEquals(1, f.repository.restoreArchives())
        val restored = f.repository.read().second.profiles
        assertTrue(restored.contains(edited))
        assertTrue(restored.contains(damaged.copy(autoConnect = false)))
        assertEquals(listOf(original), f.storage.state.archives)
        assertEquals(0, f.repository.restoreArchives())
    }

    @Test fun failedArchiveRestorationRetainsCurrentProfilesAndArchive() {
        val f = fixture()
        val original = f.storage.state.current
        assertTrue(f.repository.recover(original))
        val before = f.storage.state
        f.codec.documents[original.encoded!!] = ProfileReadResult(listOf(healthy, damaged))
        f.storage.failCommits = true
        assertEquals(-1, f.repository.restoreArchives())
        assertEquals(before, f.storage.state)
    }

    @Test fun ordinarySaveAndDeleteStillPreserveSingleAutoConnectProfile() {
        val f = fixture()
        assertTrue(f.repository.recover(f.storage.state.current))
        assertTrue(f.repository.save(added.copy(autoConnect = true)))
        assertEquals(listOf(added.id), f.repository.read().second.profiles.filter { it.autoConnect }.map { it.id })
        val before = f.storage.state
        f.storage.failCommits = true
        assertFalse(f.repository.delete(added.id))
        assertEquals(before, f.storage.state)
        f.storage.failCommits = false
        assertTrue(f.repository.delete(added.id))
        assertEquals(listOf(healthy.id), f.repository.read().second.profiles.map { it.id })
    }
}
