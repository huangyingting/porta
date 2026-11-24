package dev.porta.android

private val IPV4_RELAY = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?$""")
private val IPV6_RELAY = Regex("""^\[([0-9A-Fa-f:.]+)](?::(\d{1,5}))?$|^([0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*)$""")

/**
 * Whether [value] can name a relay that forwards TCP and UDP to a profile's
 * gateway: an IP literal with an optional port, such as `203.0.113.7:8443`
 * or `[2001:db8::7]:443`. Host names are refused, so dialing a relay never
 * needs a DNS lookup. The native client checks the address again.
 */
internal fun isRelayAddress(value: String): Boolean {
    val trimmed = value.trim()
    IPV4_RELAY.matchEntire(trimmed)?.let { match ->
        val octets = match.groupValues.subList(1, 5).map { it.toInt() }
        if (octets.any { it > 255 } || octets.all { it == 0 }) return false
        return validPort(match.groupValues[5])
    }
    val match = IPV6_RELAY.matchEntire(trimmed) ?: return false
    val address = match.groupValues[1].ifEmpty { match.groupValues[3] }
    if (address.count { it == ':' } < 2 || address == "::") return false
    return validPort(match.groupValues[2])
}

private fun validPort(port: String): Boolean = port.isEmpty() || port.toInt() in 1..65535
