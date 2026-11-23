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
        assertNull(parseTunnelRouting("2001:db8::/32|"))
        assertNull(parseTunnelRouting("10.20.0.0/16,2001:db8::/129|"))
        assertNull(parseTunnelRouting("10.20.0.0/16,2001:db8::1::/32|"))
    }

    @Test
    fun parsesIPv6SplitRoutesAlongsideIPv4() {
        val split = parseTunnelRouting("10.20.0.0/16,fd66::/64,2001:db8::/32|")!!
        assertEquals(3, split.routes.size)
        assertEquals(listOf(false, true, true), split.routes.map { it.isIPv6 })
        assertEquals("fd66::/64", split.routes[1].toString())
    }
}
