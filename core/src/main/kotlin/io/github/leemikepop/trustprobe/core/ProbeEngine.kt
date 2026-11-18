package io.github.leemikepop.trustprobe.core

import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import io.github.leemikepop.trustprobe.core.probe.TestScheduler
import io.github.leemikepop.trustprobe.core.socks.Relay
import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import io.github.leemikepop.trustprobe.core.socks.Socks5Server
import io.github.leemikepop.trustprobe.core.socks.TcpHandler
import io.github.leemikepop.trustprobe.core.tls.CertificateFactory
import io.github.leemikepop.trustprobe.core.tls.ClientHelloParser
import io.github.leemikepop.trustprobe.core.tls.ClientHelloResult
import io.github.leemikepop.trustprobe.core.tls.ProbeTimeouts
import io.github.leemikepop.trustprobe.core.tls.TlsProbe
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope

/**
 * Receives every connection of the app under test (through the SOCKS5 server) and decides per
 * connection: probe it with a bad certificate, forward it untouched, or (UDP to a QUIC port) drop it.
 *
 * [onEvent] and [onPlaintext] are invoked from many worker threads concurrently; callers must
 * make them thread-safe. A callback that throws never affects a connection. [onPlaintext]
 * receives the first decrypted request bytes UNREDACTED: keep them in memory only.
 *
 * [tlsPorts] are the destination ports treated as TLS (TCP) and as QUIC (UDP, dropped).
 * [connectUpstream] opens every forwarded connection, so tests can redirect upstream.
 */
class ProbeEngine(
    scope: CoroutineScope,
    private val onEvent: (EngineEvent) -> Unit,
    private val onPlaintext: (host: String, case: ProbeCase, bytes: ByteArray) -> Unit = { _, _, _ -> },
    private val timeouts: ProbeTimeouts = ProbeTimeouts(),
    private val tlsPorts: Set<Int> = setOf(443),
    private val connectUpstream: (InetSocketAddress) -> Socket = { Socket().apply { connect(it, 10_000) } },
) {
    /** The SOCKS5 credentials the tunnel must present. */
    val credentials: Socks5Credentials = Socks5Credentials.random()

    private val scheduler = TestScheduler()
    private val tlsProbe = TlsProbe(CertificateFactory(), timeouts)
    private val nonTlsSeen = ConcurrentHashMap.newKeySet<String>()
    private val quicSeen = ConcurrentHashMap.newKeySet<String>()
    @Volatile private var stopped = false

    private val server = Socks5Server(
        tcp = TcpHandler { client, dst -> handle(client, dst) },
        udpPolicy = ::udpPolicy,
        scope = scope,
        credentials = credentials,
    )

    /** Starts the SOCKS5 server on 127.0.0.1 and returns its port. */
    fun start(): Int = server.start()

    /**
     * Stops the server and closes open connections. Idempotent. No new events or plaintext are
     * delivered once stop() has begun; a callback already running may still finish.
     */
    fun stop() {
        stopped = true
        server.stop()
    }

    private fun udpPolicy(dst: InetSocketAddress): Boolean {
        if (dst.port !in tlsPorts) return true
        val name = hostPort(dst)
        if (quicSeen.add(name)) emit(EngineEvent.QuicDropped(name, now()))
        return false
    }

    private fun handle(client: Socket, dst: InetSocketAddress) {
        try {
            if (dst.port in tlsPorts) handleTls(client, dst) else handleNonTls(client, dst)
        } catch (_: Exception) {
            // A connection's failure never escapes; the socket is closed below.
        } finally {
            runCatching { client.close() }
        }
    }

    private fun handleNonTls(client: Socket, dst: InetSocketAddress) {
        val name = hostPort(dst)
        if (nonTlsSeen.add(name)) emit(EngineEvent.Forwarded(name, now(), ForwardReason.NON_TLS_PORT))
        forward(client, dst, ByteArray(0))
    }

    private fun handleTls(client: Socket, dst: InetSocketAddress) {
        val name = hostPort(dst)
        val buf = ByteArray(MAX_CLIENT_HELLO)
        var len = 0
        var parsed: ClientHelloResult? = null
        val deadline = System.nanoTime() + timeouts.handshakeMs * 1_000_000
        try {
            val input = client.getInputStream()
            while (parsed == null && len < buf.size) {
                val remainingMs = (deadline - System.nanoTime()) / 1_000_000
                if (remainingMs <= 0) break
                client.soTimeout = remainingMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                val n = input.read(buf, len, buf.size - len)
                if (n < 0) break
                len += n
                val r = ClientHelloParser.parse(buf, len)
                if (r != ClientHelloResult.NeedMore) parsed = r
            }
        } catch (_: SocketTimeoutException) {
            // Treated like EOF below.
        } catch (_: IOException) {
            return
        }
        client.soTimeout = 0
        val bytes = buf.copyOf(len)

        val hello = parsed
        if (hello is ClientHelloResult.Complete) {
            val sni = hello.sni?.trim()?.takeIf { it.isNotEmpty() }?.lowercase()
            if (sni == null) {
                emit(EngineEvent.Forwarded(name, now(), ForwardReason.NO_SNI))
                forward(client, dst, bytes)
            } else {
                routeBySni(client, dst, sni, bytes)
            }
        } else {
            // NotTls, an oversize hello, a timeout, or EOF: forward only if there is something to send.
            if (len == 0) return
            emit(EngineEvent.Forwarded(name, now(), ForwardReason.NOT_TLS))
            forward(client, dst, bytes)
        }
    }

    private fun routeBySni(client: Socket, dst: InetSocketAddress, sni: String, bytes: ByteArray) {
        val case = scheduler.assign(sni)
        if (case == null) {
            emit(EngineEvent.Forwarded(sni, now(), ForwardReason.HOST_DONE))
            forward(client, dst, bytes)
            return
        }
        val started = System.nanoTime()
        fun elapsedMs() = (System.nanoTime() - started) / 1_000_000
        var result: ProbeResult? = null
        var plaintext: ByteArray? = null
        try {
            val (r, p) = tlsProbe.run(client, bytes, sni, case)
            result = r
            plaintext = p
        } catch (e: Throwable) {
            result = ProbeResult(case, OutcomeKind.ERROR, null, e.message ?: e.javaClass.name, null, null, elapsedMs())
            runCatching { client.close() }
        } finally {
            val finalResult = result ?: ProbeResult(case, OutcomeKind.ERROR, null, "probe aborted", null, null, elapsedMs())
            scheduler.report(sni, finalResult)
            plaintext?.let { p -> if (!stopped) runCatching { onPlaintext(sni, case, p) } }
            emit(EngineEvent.Probed(sni, now(), finalResult))
        }
    }

    /** Opens upstream via [connectUpstream], sends [prefix], then pipes until both sides end. */
    private fun forward(client: Socket, dst: InetSocketAddress, prefix: ByteArray) {
        val upstream = try {
            connectUpstream(dst)
        } catch (_: Exception) {
            runCatching { client.close() }
            return
        }
        try {
            if (prefix.isNotEmpty()) upstream.getOutputStream().apply { write(prefix); flush() }
        } catch (_: IOException) {
            runCatching { upstream.close() }
            runCatching { client.close() }
            return
        }
        Relay.pipe(client, upstream)
    }

    private fun emit(event: EngineEvent) {
        if (stopped) return
        runCatching { onEvent(event) }
    }

    private fun hostPort(dst: InetSocketAddress): String {
        val host = dst.hostString
        return if (host.contains(':') && !host.startsWith("[")) "[$host]:${dst.port}" else "$host:${dst.port}"
    }

    private fun now() = System.currentTimeMillis()

    private companion object {
        const val MAX_CLIENT_HELLO = 16 * 1024
    }
}
