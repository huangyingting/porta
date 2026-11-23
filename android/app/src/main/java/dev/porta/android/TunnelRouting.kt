package dev.porta.android

/** A destination prefix the gateway routes through the tunnel. */
internal data class RoutePrefix(val address: String, val prefixLength: Int) {
    val isIPv6: Boolean
        get() = address.contains(':')

    override fun toString(): String = "$address/$prefixLength"
}

/** Destinations the gateway tunnels; no routes means a full tunnel. */
internal data class TunnelRouting(
    val routes: List<RoutePrefix> = emptyList(),
    val dnsDomains: List<String> = emptyList(),
) {
    val isFullTunnel: Boolean
        get() = routes.isEmpty()

    /**
     * Android has no per-domain resolver for a VPN, so a split tunnel uses the
     * tunnel resolver only when the gateway advertises DNS domains.
     */
    val usesTunnelDns: Boolean
        get() = isFullTunnel || dnsDomains.isNotEmpty()
}

/**
 * Parses the native bridge's `route,route|domain,domain` encoding. Malformed
 * input yields null because guessing a split could leak traffic.
 */
internal fun parseTunnelRouting(value: String): TunnelRouting? {
    val fields = value.split('|')
    if (fields.size != 2) return null
    val routes = fields[0].split(',').filter { it.isNotEmpty() }.map { route ->
        val parts = route.split('/')
        if (parts.size != 2) return null
        val maximum = when {
            parseIPv4Address(parts[0]) != null -> 32
            parseIPv6Address(parts[0]) != null -> 128
            else -> return null
        }
        val length = parts[1].toIntOrNull()?.takeIf { it in 1..maximum } ?: return null
        RoutePrefix(parts[0], length)
    }
    val domains = fields[1].split(',').filter { it.isNotEmpty() }
    val ipv4Routes = routes.count { !it.isIPv6 }
    if ((domains.isNotEmpty() || routes.isNotEmpty()) && ipv4Routes == 0) return null
    return TunnelRouting(routes, domains)
}
