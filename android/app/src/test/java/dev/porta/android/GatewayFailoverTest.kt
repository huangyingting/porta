package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GatewayFailoverTest {
    @Test
    fun fasterCandidatesComeFirstAndSilentOnesLast() {
        val candidates = listOf(
            GatewayCandidate("https://a.example", "192.0.2.1"),
            GatewayCandidate("https://b.example", "192.0.2.2"),
            GatewayCandidate("https://c.example", "192.0.2.3"),
            GatewayCandidate("https://d.example", "192.0.2.4"),
        )
        assertEquals(
            listOf(candidates[2], candidates[0], candidates[1], candidates[3]),
            orderCandidates(candidates, listOf(80L, null, 5L, null)),
        )
        val probed = probeCandidates(candidates) { candidate ->
            if (candidate.address.endsWith("2")) error("unreachable") else candidate.address.last().code.toLong()
        }
        assertNull(probed[1])
        assertEquals(listOf(candidates[0], candidates[2], candidates[3], candidates[1]), orderCandidates(candidates, probed))
    }

    @Test
    fun backupServersAreHttpsOriginsWithoutDuplicates() {
        assertEquals(
            listOf("https://b.example:8443", "https://c.example"),
            parseBackupServers(" https://b.example:8443/,\nhttps://c.example  https://c.example"),
        )
        assertEquals(emptyList<String>(), parseBackupServers(""))
        assertNull(parseBackupServers("http://b.example"))
        assertNull(parseBackupServers((1..8).joinToString(",") { "https://g$it.example" }))
    }
}
