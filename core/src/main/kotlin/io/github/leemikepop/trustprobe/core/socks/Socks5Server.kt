package io.github.leemikepop.trustprobe.core.socks

import java.io.Closeable
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.plus

/** Called on an IO thread after a successful CONNECT reply. Must close [client]. */
fun interface TcpHandler {
    fun handle(client: Socket, dst: InetSocketAddress)
}

/**
 * Minimal SOCKS5 server on 127.0.0.1: no-auth, CONNECT and UDP ASSOCIATE.
 * [udpPolicy] returns true to forward a datagram to its destination.
 */
class Socks5Server(
    private val tcp: TcpHandler,
    private val udpPolicy: (InetSocketAddress) -> Boolean,
    scope: CoroutineScope,
) {
    private val job = SupervisorJob(scope.coroutineContext[Job])
    private val ioScope = scope + job + Dispatchers.IO
    private val open = ConcurrentHashMap.newKeySet<Closeable>()
    private val lock = Any()
    private var listener: ServerSocket? = null
    private var stopped = false

    /** Binds 127.0.0.1:0 and returns the port. */
    fun start(): Int {
        val server = synchronized(lock) {
            check(listener == null && !stopped) { "already started" }
            ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")).also { listener = it }
        }
        ioScope.launch { acceptLoop(server) }
        return server.localPort
    }

    fun stop() {
        synchronized(lock) {
            if (stopped) return
            stopped = true
        }
        job.cancel()
        closeQuietly(listener)
        open.toList().forEach { closeQuietly(it) }
        open.clear()
    }

    private fun acceptLoop(server: ServerSocket) {
        while (true) {
            val client = try { server.accept() } catch (_: IOException) { return }
            if (!track(client)) return
            ioScope.launch { handleClient(client) }
        }
    }

    /** Registers a resource for stop(); closes it and returns false if already stopped. */
    private fun track(c: Closeable): Boolean {
        open.add(c)
        if (synchronized(lock) { stopped }) {
            closeQuietly(c)
            open.remove(c)
            return false
        }
        return true
    }

    private fun handleClient(client: Socket) {
        var handedOff = false
        try {
            client.tcpNoDelay = true
            val input = client.getInputStream()
            val output = client.getOutputStream()
            if (!Socks5Codec.readGreeting(input)) {
                output.write(byteArrayOf(5, 0xFF.toByte())); return
            }
            output.write(byteArrayOf(5, 0))
            val req = try {
                Socks5Codec.readRequest(input)
            } catch (_: Socks5Codec.UnsupportedAddressType) {
                output.write(Socks5Codec.reply(Socks5Codec.REP_ADDRESS_TYPE_NOT_SUPPORTED)); return
            }
            when (req.cmd) {
                Socks5Codec.CMD_CONNECT -> {
                    output.write(Socks5Codec.reply(Socks5Codec.REP_OK))
                    output.flush()
                    handedOff = true
                    try { tcp.handle(client, req.dst) } finally {
                        closeQuietly(client); open.remove(client)
                    }
                }
                Socks5Codec.CMD_UDP_ASSOCIATE -> udpAssociate(client)
                else -> output.write(Socks5Codec.reply(Socks5Codec.REP_COMMAND_NOT_SUPPORTED))
            }
        } catch (_: IOException) {
        } catch (_: IllegalArgumentException) {
        } finally {
            if (!handedOff) { closeQuietly(client); open.remove(client) }
        }
    }

    /** Serves one association until the control connection [control] closes. */
    private fun udpAssociate(control: Socket) {
        val loopback = InetAddress.getByName("127.0.0.1")
        val clientSide = DatagramSocket(0, loopback)
        val upstream = DatagramSocket()
        if (!track(clientSide) || !track(upstream)) {
            closeQuietly(clientSide); closeQuietly(upstream); return
        }
        try {
            val bind = InetSocketAddress(loopback, clientSide.localPort)
            control.getOutputStream().apply { write(Socks5Codec.reply(Socks5Codec.REP_OK, bind)); flush() }
            val holder = java.util.concurrent.atomic.AtomicReference<InetSocketAddress?>()

            ioScope.launch { // client -> upstream
                val buf = ByteArray(65535)
                try {
                    while (true) {
                        val p = DatagramPacket(buf, buf.size)
                        clientSide.receive(p)
                        holder.set(InetSocketAddress(p.address, p.port))
                        val pkt = Socks5Codec.parseUdp(buf, p.length) ?: continue
                        if (pkt.dst.isUnresolved || !udpPolicy(pkt.dst)) continue
                        upstream.send(DatagramPacket(pkt.payload, pkt.payload.size, pkt.dst))
                    }
                } catch (_: IOException) {
                } finally {
                    closeQuietly(clientSide); closeQuietly(upstream)
                }
            }
            ioScope.launch { // upstream -> client
                val buf = ByteArray(65535)
                try {
                    while (true) {
                        val p = DatagramPacket(buf, buf.size)
                        upstream.receive(p)
                        val to = holder.get() ?: continue
                        val wrapped = Socks5Codec.encodeUdp(InetSocketAddress(p.address, p.port), buf, p.length)
                        clientSide.send(DatagramPacket(wrapped, wrapped.size, to))
                    }
                } catch (_: IOException) {
                } finally {
                    closeQuietly(clientSide); closeQuietly(upstream)
                }
            }
            // Block until the control connection ends (EOF or error).
            val sink = ByteArray(256)
            while (control.getInputStream().read(sink) >= 0) { /* ignore */ }
        } finally {
            closeQuietly(clientSide); closeQuietly(upstream)
            open.remove(clientSide); open.remove(upstream)
        }
    }

    private fun closeQuietly(c: Closeable?) {
        try { c?.close() } catch (_: IOException) {}
    }
}
