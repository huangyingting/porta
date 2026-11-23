package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelRoutingTest {
    @Test
    fun parsesFullAndSplitRouting() {
        val full = parseTunnelRouting("|")!!
        assertTrue(full.isFullTunnel)
        assertTrue(full.usesTunnelDns)

        val split = parseTunnelRouting("10.20.0.0/16,192.168.5.0/24|")!!
        assertFalse(split.isFullTunnel)
        assertFalse(split.usesTunnelDns)
        assertEquals(listOf(RoutePrefix("10.20.0.0", 16), RoutePrefix("192.168.5.0", 24)), split.routes)

        val dns = parseTunnelRouting("10.20.0.0/16|corp.example")!!
        assertTrue(dns.usesTunnelDns)
        assertEquals(listOf("corp.example"), dns.dnsDomains)
        assertEquals("10.20.0.0/16", dns.routes.single().toString())
    }

    @Test
    fun rejectsMalformedRouting() {
        assertNull(parseTunnelRouting(""))
        assertNull(parseTunnelRouting("10.20.0.0/0|"))
        assertNull(parseTunnelRouting("10.20.0.0|"))
        assertNull(parseTunnelRouting("example.com/24|"))
        assertNull(parseTunnelRouting("|corp.example"))
    }
}
