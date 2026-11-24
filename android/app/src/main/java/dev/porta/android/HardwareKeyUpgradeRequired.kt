package dev.porta.android

/** The account requires an attested device key, and this key has none. */
internal class HardwareKeyUpgradeRequired :
    Exception("The account requires a hardware-attested device key")
