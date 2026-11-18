package io.github.leemikepop.trustprobe.core.socks

import java.io.Closeable
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.plus

/** Called on a server thread after a successful CONNECT reply. Must close [client]. */
fun interface TcpHandler {
    fun handle(client: Socket, dst: InetSocketAddress)
}

/** RFC 1929 username/password. Every app shares 127.0.0.1 on Android, so the proxy requires them. */
data class Socks5Credentials(val username: String, val password: String) {
    companion object {
        fun random(): Socks5Credentials {
            val rnd = SecureRandom()
            fun token() = ByteArray(16).also(rnd::nextBytes)
                .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
            return Socks5Credentials(token(), token())
        }
    }
}

/**
 * Minimal SOCKS5 server on 127.0.0.1: username/password auth, CONNECT and UDP ASSOCIATE.
 * [udpPolicy] returns true to forward a datagram to its destination.
 * Blocking work runs on the server's own elastic thread pool (not Dispatchers.IO).
 */
class Socks5Server(
    private val tcp: TcpHandler,
    private val udpPolicy: (InetSocketAddress) -> Boolean,
    scope: CoroutineScope,
    private val credentials: Socks5Credentials,
) {
    private val job = SupervisorJob(scope.coroutineContext[Job])
    private val dispatcher: ExecutorCoroutineDispatcher = Executors.newCachedThreadPool { r ->
        Thread(r, "socks5-worker").apply { isDaemon = true }
    }.asCoroutineDispatcher()
    private val ioScope = scope + job + dispatcher
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
        dispatcher.close()
    }

    private fun isStopped() = synchronized(lock) { stopped }

    private fun acceptLoop(server: ServerSocket) {
        while (!server.isClosed && !isStopped()) {
            val client = try {
                server.accept()
            } catch (_: Exception) {
                if (server.isClosed || isStopped()) return
                Thread.sleep(50)
                continue
            }
            if (!track(client)) return
            ioScope.launch { handleClient(client) }
        }
    }

    /** Registers a resource for stop(); closes it and returns false if already stopped. */
    private fun track(c: Closeable): Boolean {
        open.add(c)
        if (isStopped()) {
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
            client.soTimeout = HANDSHAKE_TIMEOUT_MS
            val input = client.getInputStream()
            val output = client.getOutputStream()
            if (Socks5Codec.METHOD_USER_PASS !in Socks5Codec.readGreeting(input)) {
                output.write(byteArrayOf(5, 0xFF.toByte())); return
            }
            output.write(byteArrayOf(5, Socks5Codec.METHOD_USER_PASS.toByte()))
            val (user, pass) = Socks5Codec.readAuth(input)
            if (!credentialsMatch(user, pass)) {
                output.write(byteArrayOf(1, 1)); return
            }
            output.write(byteArrayOf(1, 0))
            val req = try {
                Socks5Codec.readRequest(input)
            } catch (_: Socks5Codec.UnsupportedAddressType) {
                output.write(Socks5Codec.reply(Socks5Codec.REP_ADDRESS_TYPE_NOT_SUPPORTED)); return
            }
            when (req.cmd) {
                Socks5Codec.CMD_CONNECT -> {
                    output.write(Socks5Codec.reply(Socks5Codec.REP_OK))
                    output.flush()
                    client.soTimeout = 0
                    handedOff = true
                    try { tcp.handle(client, req.dst) } finally {
                        closeQuietly(client); open.remove(client)
                    }
                }
                Socks5Codec.CMD_UDP_ASSOCIATE -> {
                    client.soTimeout = 0
                    udpAssociate(client)
                }
                else -> output.write(Socks5Codec.reply(Socks5Codec.REP_COMMAND_NOT_SUPPORTED))
            }
        } catch (_: Exception) {
            // IO errors, malformed requests, or a throwing TcpHandler: this client only.
        } finally {
            if (!handedOff) { closeQuietly(client); open.remove(client) }
        }
    }

    private fun credentialsMatch(user: ByteArray, pass: ByteArray): Boolean {
        val okUser = MessageDigest.isEqual(user, credentials.username.toByteArray())
        val okPass = MessageDigest.isEqual(pass, credentials.password.toByteArray())
        return okUser and okPass
    }

    /** Serves one association until the control connection [control] closes. */
    private fun udpAssociate(control: Socket) {
        val loopback = InetAddress.getByName("127.0.0.1")
        var clientSide: DatagramSocket? = null
        var upstream: DatagramSocket? = null
        try {
            clientSide = DatagramSocket(0, loopback)
            upstream = DatagramSocket()
            if (!track(clientSide) || !track(upstream)) return
            val cs = clientSide
            val up = upstream
            val controlIp = control.inetAddress
            val bind = InetSocketAddress(loopback, cs.localPort)
            control.getOutputStream().apply { write(Socks5Codec.reply(Socks5Codec.REP_OK, bind)); flush() }
            val locked = AtomicReference<InetSocketAddress?>()

            fun shutdown() { closeQuietly(cs); closeQuietly(up); closeQuietly(control) }

            ioScope.launch { // client -> upstream
                val buf = ByteArray(65535)
                try {
                    while (!cs.isClosed) {
                        val p = DatagramPacket(buf, buf.size)
                        try { cs.receive(p) } catch (_: Exception) {
                            if (cs.isClosed) break
                            Thread.sleep(50); continue
                        }
                        try {
                            val src = InetSocketAddress(p.address, p.port)
                            val current = locked.get()
                            if (current == null) {
                                if (p.address != controlIp) continue
                            } else if (current != src) continue
                            val pkt = Socks5Codec.parseUdp(buf, p.length) ?: continue
                            if (current == null) locked.set(src)
                            if (pkt.dst.isUnresolved || !udpPolicy(pkt.dst)) continue
                            up.send(DatagramPacket(pkt.payload, pkt.payload.size, pkt.dst))
                        } catch (_: Exception) { /* drop this packet only */ }
                    }
                } finally { shutdown() }
            }
            ioScope.launch { // upstream -> client
                val buf = ByteArray(65535)
                try {
                    while (!up.isClosed) {
                        val p = DatagramPacket(buf, buf.size)
                        try { up.receive(p) } catch (_: Exception) {
                            if (up.isClosed) break
                            Thread.sleep(50); continue
                        }
                        try {
                            val to = locked.get() ?: continue
                            val wrapped = Socks5Codec.encodeUdp(InetSocketAddress(p.address, p.port), buf, p.length)
                            cs.send(DatagramPacket(wrapped, wrapped.size, to))
                        } catch (_: Exception) { /* drop this packet only */ }
                    }
                } finally { shutdown() }
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

    private companion object {
        const val HANDSHAKE_TIMEOUT_MS = 10_000
    }
}
