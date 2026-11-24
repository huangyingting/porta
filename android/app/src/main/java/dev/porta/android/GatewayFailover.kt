package dev.porta.android

import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** One endpoint of one gateway in a profile. */
internal data class GatewayCandidate(val server: String, val address: String)

/** How long a latency probe waits for one endpoint. */
internal const val GATEWAY_PROBE_TIMEOUT_MILLIS = 1500

/**
 * Orders candidates fastest first. Endpoints that did not answer follow in
 * their listed order, so failover still reaches them.
 */
internal fun orderCandidates(
    candidates: List<GatewayCandidate>,
    latencies: List<Long?>,
): List<GatewayCandidate> = candidates.indices
    .sortedWith(compareBy({ latencies.getOrNull(it) == null }, { latencies.getOrNull(it) ?: 0L }, { it }))
    .map { candidates[it] }

/** Measures every candidate's TCP connect time concurrently. */
internal fun probeCandidates(
    candidates: List<GatewayCandidate>,
    connect: (GatewayCandidate) -> Long?,
): List<Long?> {
    if (candidates.size < 2) return candidates.map { null }
    val executor = Executors.newFixedThreadPool(minOf(candidates.size, 8))
    return try {
        executor.invokeAll(
            candidates.map { candidate -> Callable { runCatching { connect(candidate) }.getOrNull() } },
            GATEWAY_PROBE_TIMEOUT_MILLIS + 500L,
            TimeUnit.MILLISECONDS,
        ).map { future -> runCatching { future.get() }.getOrNull() }
    } finally {
        executor.shutdownNow()
    }
}

/** The milliseconds a TCP handshake with [address] takes, or null. */
internal fun tcpConnectMillis(socket: Socket, address: String, port: Int): Long? = socket.use {
    val started = System.nanoTime()
    it.connect(InetSocketAddress(address, port), GATEWAY_PROBE_TIMEOUT_MILLIS)
    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
}

/** Parses the backup gateway field: HTTPS origins separated by lines or commas. */
internal fun parseBackupServers(text: String): List<String>? {
    val servers = text.split('\n', ',', ' ').map { it.trim().trimEnd('/') }.filter { it.isNotEmpty() }
    if (servers.size > 7 || servers.any { !isHttpsOrigin(it) }) return null
    return servers.distinct()
}
