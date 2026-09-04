package dev.porta.android

// A failed reader remains attached until a transport connects and can replace its VPN.
// Only a new failure can have canceled this dial; an existing one must allow H2 fallback.
internal fun hasNewVpnReaderFailure(beforeDial: Exception?, afterDial: Exception?): Boolean =
    afterDial != null && afterDial !== beforeDial
