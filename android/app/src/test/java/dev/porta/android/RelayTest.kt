package dev.porta.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayTest {
    @Test
    fun relaysAreIpLiteralsWithOptionalPorts() {
        for (valid in listOf("203.0.113.7", "203.0.113.7:8443", " 198.51.100.1:443 ", "[2001:db8::7]:443", "2001:db8::7")) {
            assertTrue(valid, isRelayAddress(valid))
        }
        for (invalid in listOf("", "relay.example.com", "relay.example.com:443", "203.0.113.7:0", "203.0.113.7:70000",
            "256.1.1.1", "0.0.0.0", "1.2.3", "::", "[2001:db8::7]:", "https://203.0.113.7")) {
            assertFalse(invalid, isRelayAddress(invalid))
        }
    }
}
