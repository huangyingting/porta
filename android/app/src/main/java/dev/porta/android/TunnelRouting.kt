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

/**
 * Prefixes covering the whole IPv4 or IPv6 space except [excluded], so a full
 * tunnel can route around local networks on every Android version.
 */
internal fun routesExcluding(ipv6: Boolean, excluded: List<RoutePrefix>): List<RoutePrefix> {
    val bits = if (ipv6) 128 else 32
    val holes = excluded.filter { it.isIPv6 == ipv6 }.mapNotNull { prefix ->
        val address = addressBytes(prefix.address) ?: return@mapNotNull null
        java.math.BigInteger(1, address) to prefix.prefixLength
    }
    val routes = mutableListOf<RoutePrefix>()
    fun cover(start: java.math.BigInteger, length: Int) {
        val size = java.math.BigInteger.ONE.shiftLeft(bits - length)
        val end = start + size
        val overlapping = holes.filter { (hole, holeLength) ->
            val holeEnd = hole + java.math.BigInteger.ONE.shiftLeft(bits - holeLength)
            hole < end && start < holeEnd
        }
        when {
            overlapping.isEmpty() -> routes += RoutePrefix(formatAddress(start, bits), length)
            overlapping.any { (hole, holeLength) -> holeLength <= length && start >= hole } -> Unit
            else -> {
                cover(start, length + 1)
                cover(start + size.shiftRight(1), length + 1)
            }
        }
    }
    cover(java.math.BigInteger.ZERO, 0)
    return routes
}

/**
 * The network of an interface address when it is private (RFC 1918,
 * link-local, or IPv6 unique local) and does not contain [keep], the
 * tunnel's own addresses.
 */
internal fun localNetworkPrefix(address: ByteArray, prefixLength: Int, keep: List<ByteArray>): RoutePrefix? {
    val bits = address.size * 8
    if (bits != 32 && bits != 128 || prefixLength !in (if (bits == 32) 8 else 48)..bits) return null
    val first = address[0].toInt() and 0xff
    val second = address[1].toInt() and 0xff
    val private = if (bits == 32) {
        first == 10 || (first == 172 && second in 16..31) || (first == 192 && second == 168) ||
            (first == 169 && second == 254)
    } else {
        first and 0xfe == 0xfc
    }
    if (!private) return null
    val mask = java.math.BigInteger.ONE.shiftLeft(bits).subtract(java.math.BigInteger.ONE)
        .xor(java.math.BigInteger.ONE.shiftLeft(bits - prefixLength).subtract(java.math.BigInteger.ONE))
    val network = java.math.BigInteger(1, address).and(mask)
    if (keep.any { it.size == address.size && java.math.BigInteger(1, it).and(mask) == network }) return null
    return RoutePrefix(formatAddress(network, bits), prefixLength)
}

private fun addressBytes(value: String): ByteArray? = parseIPv4Address(value) ?: parseIPv6Address(value)

private fun formatAddress(value: java.math.BigInteger, bits: Int): String {
    val bytes = ByteArray(bits / 8)
    val raw = value.toByteArray()
    for (index in raw.indices.reversed()) {
        val target = bytes.size - (raw.size - index)
        if (target >= 0) bytes[target] = raw[index]
    }
    return if (bits == 32) {
        bytes.joinToString(".") { (it.toInt() and 0xff).toString() }
    } else {
        java.net.InetAddress.getByAddress(bytes).hostAddress.orEmpty()
    }
}
