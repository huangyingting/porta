package dev.porta.android

import android.net.Network
import android.net.VpnService
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

class ProtectedSocketFactory(
    private val service: VpnService,
    private val network: () -> Network?,
) : SocketFactory() {
    private fun protectedSocket(connect: Socket.() -> Unit = {}): Socket = configureSocket(Socket()) {
        val underlyingNetwork = network()
            ?: throw IOException("No underlying network is available")
        underlyingNetwork.bindSocket(it)
        if (!service.protect(it)) {
            throw IOException("Android refused to protect the tunnel socket")
        }
        it.connect()
    }

    override fun createSocket(): Socket = protectedSocket()

    override fun createSocket(host: String, port: Int): Socket =
        protectedSocket { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        protectedSocket {
            bind(InetSocketAddress(localHost, localPort))
            connect(InetSocketAddress(host, port))
        }

    override fun createSocket(host: InetAddress, port: Int): Socket =
        protectedSocket { connect(InetSocketAddress(host, port)) }

    override fun createSocket(
        address: InetAddress,
        port: Int,
        localAddress: InetAddress,
        localPort: Int,
    ): Socket = protectedSocket {
        bind(InetSocketAddress(localAddress, localPort))
        connect(InetSocketAddress(address, port))
    }
}

internal fun configureSocket(socket: Socket, configure: (Socket) -> Unit): Socket {
    try {
        configure(socket)
        return socket
    } catch (error: Exception) {
        try {
            socket.close()
        } catch (closeError: Exception) {
            error.addSuppressed(closeError)
        }
        throw error
    }
}
