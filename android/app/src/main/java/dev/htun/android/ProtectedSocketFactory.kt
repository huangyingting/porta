package dev.htun.android

import android.net.VpnService
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

class ProtectedSocketFactory(private val service: VpnService) : SocketFactory() {
    private fun protectedSocket(): Socket {
        val socket = Socket()
        if (!service.protect(socket)) {
            socket.close()
            throw IllegalStateException("Android refused to protect the tunnel socket")
        }
        return socket
    }

    override fun createSocket(): Socket = protectedSocket()

    override fun createSocket(host: String, port: Int): Socket =
        protectedSocket().apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        protectedSocket().apply {
            bind(InetSocketAddress(localHost, localPort))
            connect(InetSocketAddress(host, port))
        }

    override fun createSocket(host: InetAddress, port: Int): Socket =
        protectedSocket().apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(
        address: InetAddress,
        port: Int,
        localAddress: InetAddress,
        localPort: Int,
    ): Socket = protectedSocket().apply {
        bind(InetSocketAddress(localAddress, localPort))
        connect(InetSocketAddress(address, port))
    }
}

