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

    @Test
    fun localNetworksAreRoutedAroundExactlyInBothFamilies() {
        val excluded = listOf(RoutePrefix("192.168.1.0", 24), RoutePrefix("224.0.0.0", 4))
        val routes = routesExcluding(ipv6 = false, excluded)
        fun covered(address: String) = routes.any { route ->
            val target = java.math.BigInteger(1, parseIPv4Address(address)!!)
            val start = java.math.BigInteger(1, parseIPv4Address(route.address)!!)
            target >= start && target < start + java.math.BigInteger.ONE.shiftLeft(32 - route.prefixLength)
        }
        for (address in listOf("0.0.0.1", "8.8.8.8", "10.66.0.1", "192.168.0.255", "192.168.2.0", "223.255.255.255", "240.0.0.1")) {
            assertTrue(address, covered(address))
        }
        for (address in listOf("192.168.1.0", "192.168.1.77", "224.0.0.251", "239.255.255.250")) {
            assertFalse(address, covered(address))
        }
        assertEquals(listOf(RoutePrefix("0.0.0.0", 0)), routesExcluding(ipv6 = false, emptyList()))

        val routes6 = routesExcluding(ipv6 = true, listOf(RoutePrefix("fd12:3456::", 64)))
        assertTrue(routes6.all { it.isIPv6 })
        assertFalse(routes6.any { it.address.startsWith("fd12:3456:0:0") && it.prefixLength >= 64 })
        assertEquals(64, routes6.size)
    }

    @Test
    fun onlyPrivateNetworksWithoutTunnelAddressesAreLocal() {
        val keep = listOf(parseIPv4Address("10.66.0.2")!!, parseIPv4Address("10.66.0.1")!!)
        assertEquals(
            RoutePrefix("192.168.1.0", 24),
            localNetworkPrefix(parseIPv4Address("192.168.1.37")!!, 24, keep),
        )
        assertEquals(null, localNetworkPrefix(parseIPv4Address("203.0.113.5")!!, 24, keep))
        assertEquals(null, localNetworkPrefix(parseIPv4Address("10.66.0.9")!!, 24, keep))
        assertEquals(null, localNetworkPrefix(parseIPv4Address("10.1.2.3")!!, 4, keep))
        assertEquals(
            RoutePrefix("fd12:3456:0:0:0:0:0:0", 64),
            localNetworkPrefix(parseIPv6Address("fd12:3456::9")!!, 64, keep),
        )
        assertEquals(null, localNetworkPrefix(parseIPv6Address("2001:db8::9")!!, 64, keep))
    }
}
