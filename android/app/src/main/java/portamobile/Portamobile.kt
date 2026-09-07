package portamobile

import android.content.Context
import java.io.IOException
import java.util.concurrent.atomic.AtomicLong

fun interface Protector {
    fun prepare(fd: Int): String
}

fun interface ProofProvider {
    fun proof(method: String, path: String): String
}

internal enum class NativeFailureKind {
    TRANSPORT_UNAVAILABLE,
    RETRYABLE,
    PERMANENT,
}

internal fun nativeFailureKind(message: String): NativeFailureKind {
    val normalized = message.removePrefix("Rust error: ")
    return when {
        normalized.startsWith("transport unavailable: ") ->
            NativeFailureKind.TRANSPORT_UNAVAILABLE
        normalized.startsWith("retryable: ") || normalized == "tunnel is closed" ->
            NativeFailureKind.RETRYABLE
        else -> NativeFailureKind.PERMANENT
    }
}

class Dialer internal constructor(handle: Long) : AutoCloseable {
    private val handle = AtomicLong(handle)

    fun dial(
        server: String,
        token: String,
        remoteIP: String,
        proofProvider: ProofProvider,
        protector: Protector,
    ): Session {
        val activeHandle = handle.get()
        if (activeHandle == 0L) throw IOException("tunnel dialer is closed")
        return Session(
            Portamobile.callNative {
                Portamobile.dial(
                    activeHandle,
                    server,
                    token,
                    remoteIP,
                    proofProvider,
                    protector,
                )
            },
        )
    }

    override fun close() {
        val activeHandle = handle.getAndSet(0)
        if (activeHandle != 0L) Portamobile.closeDialer(activeHandle)
    }
}

class Session internal constructor(handle: Long) : AutoCloseable {
    private val handle = AtomicLong(handle)

    fun send(packet: ByteArray) {
        Portamobile.callNative { Portamobile.sessionSend(requireHandle(), packet) }
    }

    fun receive(): ByteArray =
        Portamobile.callNative { Portamobile.sessionReceive(requireHandle()) }

    fun address(): String =
        Portamobile.callNative { Portamobile.sessionAddress(requireHandle()) }

    fun prefixLength(): Int =
        Portamobile.callNative { Portamobile.sessionPrefixLength(requireHandle()) }

    fun mtu(): Int =
        Portamobile.callNative { Portamobile.sessionMTU(requireHandle()) }

    fun dns(): String =
        Portamobile.callNative { Portamobile.sessionDNS(requireHandle()) }

    fun automaticMTU(): Boolean =
        Portamobile.callNative { Portamobile.sessionAutomaticMTU(requireHandle()) }

    fun maximumMTU(): Int =
        Portamobile.callNative { Portamobile.sessionMaximumMTU(requireHandle()) }

    fun packetDeliveryMode(): String =
        Portamobile.callNative { Portamobile.sessionPacketDeliveryMode(requireHandle()) }

    fun transport(): String =
        Portamobile.callNative { Portamobile.sessionTransport(requireHandle()) }

    override fun close() {
        val activeHandle = handle.getAndSet(0)
        if (activeHandle != 0L) Portamobile.closeSession(activeHandle)
    }

    private fun requireHandle(): Long =
        handle.get().takeIf { it != 0L } ?: throw IOException("tunnel is closed")
}

object Portamobile {
    init {
        System.loadLibrary("porta_android")
    }

    fun initialize(context: Context) {
        callNative { nativeInitialize(context.applicationContext) }
    }

    fun version(): String = callNative { nativeVersion() }

    fun newDialer(): Dialer = Dialer(callNative { nativeNewDialer() })

    fun deviceID(publicKey: ByteArray): String =
        callNative { nativeDeviceIDFromPublicKey(publicKey) }

    fun deviceProofMessage(
        token: String,
        method: String,
        path: String,
        deviceID: String,
        deviceName: String,
        timestamp: String,
        nonce: String,
    ): ByteArray = callNative {
        nativeDeviceProofMessage(
            token,
            method,
            path,
            deviceID,
            deviceName,
            timestamp,
            nonce,
        )
    }

    fun isTransportUnavailable(message: String): Boolean =
        nativeFailureKind(message) == NativeFailureKind.TRANSPORT_UNAVAILABLE

    fun isRetryable(message: String): Boolean =
        nativeFailureKind(message) != NativeFailureKind.PERMANENT

    internal fun <T> callNative(block: () -> T): T =
        try {
            block()
        } catch (error: RuntimeException) {
            throw IOException(normalizeMessage(error), error)
        }

    internal fun dial(
        dialer: Long,
        server: String,
        token: String,
        remoteIP: String,
        proofProvider: ProofProvider,
        protector: Protector,
    ): Long = nativeDial(
        dialer,
        server,
        token,
        remoteIP,
        proofProvider,
        protector,
    )

    internal fun closeDialer(handle: Long) = nativeCloseDialer(handle)
    internal fun sessionSend(handle: Long, packet: ByteArray) = nativeSessionSend(handle, packet)
    internal fun sessionReceive(handle: Long): ByteArray = nativeSessionReceive(handle)
    internal fun sessionAddress(handle: Long): String = nativeSessionAddress(handle)
    internal fun sessionPrefixLength(handle: Long): Int = nativeSessionPrefixLength(handle)
    internal fun sessionMTU(handle: Long): Int = nativeSessionMTU(handle)
    internal fun sessionDNS(handle: Long): String = nativeSessionDNS(handle)
    internal fun sessionAutomaticMTU(handle: Long): Boolean = nativeSessionAutomaticMTU(handle)
    internal fun sessionMaximumMTU(handle: Long): Int = nativeSessionMaximumMTU(handle)
    internal fun sessionPacketDeliveryMode(handle: Long): String =
        nativeSessionPacketDeliveryMode(handle)
    internal fun sessionTransport(handle: Long): String = nativeSessionTransport(handle)
    internal fun closeSession(handle: Long) = nativeCloseSession(handle)

    private fun normalizeMessage(error: RuntimeException): String =
        (error.message ?: "native tunnel failed").removePrefix("Rust error: ")

    @JvmStatic private external fun nativeInitialize(context: Context): Boolean
    @JvmStatic private external fun nativeVersion(): String
    @JvmStatic private external fun nativeNewDialer(): Long
    @JvmStatic private external fun nativeCloseDialer(handle: Long)
    @JvmStatic private external fun nativeDeviceIDFromPublicKey(publicKey: ByteArray): String
    @JvmStatic private external fun nativeDeviceProofMessage(
        token: String,
        method: String,
        path: String,
        deviceID: String,
        deviceName: String,
        timestamp: String,
        nonce: String,
    ): ByteArray
    @JvmStatic private external fun nativeDial(
        dialer: Long,
        server: String,
        token: String,
        remoteIP: String,
        proofProvider: ProofProvider,
        protector: Protector,
    ): Long
    @JvmStatic private external fun nativeSessionSend(handle: Long, packet: ByteArray)
    @JvmStatic private external fun nativeSessionReceive(handle: Long): ByteArray
    @JvmStatic private external fun nativeSessionAddress(handle: Long): String
    @JvmStatic private external fun nativeSessionPrefixLength(handle: Long): Int
    @JvmStatic private external fun nativeSessionMTU(handle: Long): Int
    @JvmStatic private external fun nativeSessionDNS(handle: Long): String
    @JvmStatic private external fun nativeSessionAutomaticMTU(handle: Long): Boolean
    @JvmStatic private external fun nativeSessionMaximumMTU(handle: Long): Int
    @JvmStatic private external fun nativeSessionPacketDeliveryMode(handle: Long): String
    @JvmStatic private external fun nativeSessionTransport(handle: Long): String
    @JvmStatic private external fun nativeCloseSession(handle: Long)
}
