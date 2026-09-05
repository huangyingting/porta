package dev.porta.android

import java.net.URI
import java.net.URISyntaxException
import java.util.Locale

private const val DIAGNOSTIC_MESSAGE_LIMIT = 180
private val URL_PATTERN = Regex("""https?://\S+""", RegexOption.IGNORE_CASE)

internal data class ConnectionTelemetry(
    val transport: String,
    val mtu: Int,
    val automaticMtu: Boolean,
    val address: String,
    val dns: String,
    val deliveryMode: String? = null,
    val mtuCeiling: Int? = null,
    val networkType: String? = null,
    val setupDurationMillis: Long = 0,
    val appVersion: String = "",
    val protocolVersion: String = "",
)

internal fun ConnectionTelemetry.toConnectionDetails(): ConnectionDetails =
    ConnectionDetails(
        mtu = mtu,
        automaticMtu = automaticMtu,
        mtuCeiling = mtuCeiling,
        address = address,
        dns = dns,
        transport = transport,
        deliveryMode = deliveryMode,
        networkType = networkType,
        setupDurationMillis = setupDurationMillis,
        appVersion = appVersion,
        protocolVersion = protocolVersion,
    )

internal fun formatAttemptEvent(transport: String, networkType: String?): String =
    buildString {
        append("Trying ")
        append(transport)
        if (!networkType.isNullOrBlank()) {
            append(" over ")
            append(networkType)
        }
    }

internal fun formatHttp2LaneDiagnostic(
    lane: Int,
    queue: PacketQueueSnapshot,
    reconnects: Int,
): String =
    "HTTP/2 lane $lane: drops ${queue.totalDrops}; high-water " +
        "${queue.highWaterBytes}B/${queue.highWaterPackets}p; " +
        "oldest ${queue.oldestAgeMillis}ms; reconnects $reconnects"

internal fun formatConnectedEvents(telemetry: ConnectionTelemetry): List<String> = listOf(
    buildString {
        append("Connected over ")
        append(telemetry.transport)
        append(" in ")
        append(formatDuration(telemetry.setupDurationMillis))
        if (!telemetry.networkType.isNullOrBlank()) {
            append(" via ")
            append(telemetry.networkType)
        }
        if (!telemetry.deliveryMode.isNullOrBlank()) {
            append(" using ")
            append(telemetry.deliveryMode)
        }
    },
    buildString {
        append("Lease ")
        append(telemetry.address)
        if (telemetry.dns.isNotBlank()) {
            append("; DNS ")
            append(telemetry.dns)
        }
        append("; MTU ")
        append(telemetry.mtu)
        append(" (")
        append(if (telemetry.automaticMtu) "automatic" else "server-configured")
        telemetry.mtuCeiling?.let {
            if (telemetry.automaticMtu) {
                append(", ceiling ")
                append(it)
            }
        }
        append(")")
        if (telemetry.appVersion.isNotBlank()) {
            append("; app ")
            append(telemetry.appVersion)
        }
        if (telemetry.protocolVersion.isNotBlank()) {
            append("; proto ")
            append(telemetry.protocolVersion)
        }
    },
)

internal fun diagnosticFailureDetail(error: Exception, token: String): String {
    val base = redactDiagnosticMessage(error.message.orEmpty(), token)
        .ifBlank { error.javaClass.simpleName }
    val hint = authenticationFailureHint(base) ?: return base
    return "$base; $hint".take(DIAGNOSTIC_MESSAGE_LIMIT)
}

internal fun redactDiagnosticMessage(message: String, token: String): String {
    val withoutToken = if (token.isEmpty()) message else message.replace(token, "[redacted]")
    return normalizeClassifiedMessage(
        URL_PATTERN.replace(withoutToken) { match -> sanitizeDiagnosticUrl(match.value) }
            .replace(
                Regex("""(?:Proxy-)?Authorization:?\s+(?:Bearer|Basic)\s+\S+""", RegexOption.IGNORE_CASE),
                "authorization [redacted]",
            )
            .replace(Regex("""Bearer\s+\S+""", RegexOption.IGNORE_CASE), "Bearer [redacted]")
            .replace(Regex("""Basic\s+\S+""", RegexOption.IGNORE_CASE), "Basic [redacted]")
            .replace(Regex("""(?:Proxy-)?Authorization:\s*\S+""", RegexOption.IGNORE_CASE), "authorization [redacted]")
            .replace(Regex("\\s+"), " ")
            .trim(),
    ).take(DIAGNOSTIC_MESSAGE_LIMIT)
}

private fun normalizeClassifiedMessage(message: String): String {
    var normalized = message
    while (true) {
        normalized = when {
            normalized.startsWith("transport unavailable: ", ignoreCase = true) ->
                normalized.substring("transport unavailable: ".length)
            normalized.startsWith("retryable: ", ignoreCase = true) ->
                normalized.substring("retryable: ".length)
            else -> return normalized
        }.trimStart()
    }
}

private fun sanitizeDiagnosticUrl(candidate: String): String {
    val trimmed = candidate.trimEnd('.', ',', ';', ')')
    val suffix = candidate.substring(trimmed.length)
    val sanitized = try {
        val uri = URI(trimmed)
        val host = uri.host ?: return "[redacted URL]" + suffix
        buildString {
            append(uri.scheme ?: "https")
            append("://")
            append(host)
            if (uri.port >= 0) {
                append(':')
                append(uri.port)
            }
            if (!uri.path.isNullOrBlank() && uri.path != "/") append("/...")
        }
    } catch (_: URISyntaxException) {
        "[redacted URL]"
    }
    return sanitized + suffix
}

private fun authenticationFailureHint(message: String): String? {
    val normalized = message.lowercase(Locale.US)
    return if ("401 unauthorized" in normalized || "http 401" in normalized || " unauthorized" in normalized) {
        "check whether the device token is valid, enabled, and within the device limit"
    } else {
        null
    }
}

private fun formatDuration(durationMillis: Long): String =
    if (durationMillis < 1_000L) {
        "${durationMillis.coerceAtLeast(0L)}ms"
    } else {
        String.format(Locale.US, "%.1fs", durationMillis / 1_000.0)
    }
