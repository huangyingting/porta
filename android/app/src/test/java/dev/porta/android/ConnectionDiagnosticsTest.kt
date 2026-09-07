package dev.porta.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionDiagnosticsTest {
    @Test
    fun connectedEventsIncludeAutoMtuCeilingAndVersions() {
        val telemetry = ConnectionTelemetry(
            transport = "HTTP/3 MASQUE",
            mtu = 1360,
            automaticMtu = true,
            mtuCeiling = 1400,
            address = "10.66.0.2/32",
            dns = "1.1.1.1",
            deliveryMode = "datagrams",
            networkType = "Wi-Fi",
            setupDurationMillis = 842,
            appVersion = "0.1.11",
            protocolVersion = PacketFraming.VERSION,
        )

        val events = formatConnectedEvents(telemetry)

        assertEquals("Connected over HTTP/3 MASQUE in 842ms via Wi-Fi using datagrams", events[0])
        assertEquals(
            "Lease 10.66.0.2/32; DNS 1.1.1.1; MTU 1360 (automatic, ceiling 1400); app 0.1.11; proto 2",
            events[1],
        )
        assertTrue(events.all { it.length <= 240 })
    }

    @Test
    fun connectedEventsKeepHttp2ServerConfiguredMtuShort() {
        val telemetry = ConnectionTelemetry(
            transport = "multi-lane HTTP/2",
            mtu = 1300,
            automaticMtu = false,
            address = "10.66.0.2/32",
            dns = "",
            deliveryMode = "4 lanes",
            networkType = "cellular",
            setupDurationMillis = 1_240,
            appVersion = "0.1.11",
            protocolVersion = PacketFraming.VERSION,
        )

        val events = formatConnectedEvents(telemetry)

        assertEquals("Connected over multi-lane HTTP/2 in 1.2s via cellular using 4 lanes", events[0])
        assertEquals(
            "Lease 10.66.0.2/32; MTU 1300 (server-configured); app 0.1.11; proto 2",
            events[1],
        )
    }

    @Test
    fun failureDetailRedactsTokenAndSensitiveUrlPath() {
        val token = "0123456789abcdef"
        val detail = diagnosticFailureDetail(
            IllegalStateException("retryable: dial https://vpn.example.com/invite/secret?token=$token with Bearer $token"),
            token,
        )

        assertFalse(detail.contains(token))
        assertTrue(detail.contains("dial https://vpn.example.com/..."))
        assertFalse(detail.startsWith("retryable:"))
    }

    @Test
    fun failureDetailAddsAuthenticationHint() {
        val detail = diagnosticFailureDetail(
            IllegalStateException("gateway returned 401 Unauthorized"),
            "secret",
        )

        assertTrue(detail.contains("401 Unauthorized"))
        assertTrue(detail.contains("device token is valid"))
    }

    @Test
    fun redactsUnknownAuthorizationValuesAndUppercaseUrls() {
        val values = listOf(
            "Authorization: Bearer other-private-value",
            "Proxy-Authorization: Basic other-private-value",
            "Basic other-private-value",
            "Authorization: other-private-value",
            "HTTPS://user:other-private-value@vpn.example.com/path?token=other-private-value",
        )
        for (message in values) {
            assertFalse(redactDiagnosticMessage(message, "").contains("other-private-value"))
        }
        assertEquals("connection interrupted", redactDiagnosticMessage("connection interrupted", ""))
    }

    @Test
    fun malformedUrlsAreRedactedWithoutSwallowingUnrelatedFailures() {
        val message = redactDiagnosticMessage("dial https://[invalid/path?token=private", "")
        assertEquals("dial [redacted URL]", message)
    }

}
