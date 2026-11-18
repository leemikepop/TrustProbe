package io.github.leemikepop.trustprobe.core

import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.tls.CertificateFactory
import io.github.leemikepop.trustprobe.core.tls.ProbeTimeouts
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyStore
import java.nio.ByteBuffer
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProbeEngineTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val closeables = mutableListOf<AutoCloseable>()
    private val events = LinkedBlockingQueue<EngineEvent>()
    private val plaintexts = ConcurrentLinkedQueue<Triple<String, ProbeCase, ByteArray>>()
    private var engine: ProbeEngine? = null

    @After
    fun tearDown() {
        engine?.stop()
        closeables.forEach { runCatching { it.close() } }
        scope.cancel()
    }

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /** A real TLS server that answers any request with a fixed body; returns its port. */
    private fun startUpstream(): Int {
        val material = CertificateFactory().materialFor(ProbeCase.T2_UNTRUSTED_CA, "upstream.test")
        val ks = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("k", material.privateKey, CharArray(0), material.chain.toTypedArray())
        }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            .apply { init(ks, CharArray(0)) }
        val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        val server = ctx.serverSocketFactory.createServerSocket(0, 50, InetAddress.getLoopbackAddress())
            .also { closeables += it }
        thread(isDaemon = true) {
            while (!server.isClosed) {
                val s = runCatching { server.accept() }.getOrNull() ?: break
                thread(isDaemon = true) {
                    runCatching {
                        s.use {
                            it.soTimeout = 5_000
                            it.getInputStream().read(ByteArray(4096))
                            it.getOutputStream().apply { write(UPSTREAM_REPLY); flush() }
                        }
                    }
                }
            }
        }
        return server.localPort
    }

    private fun startEngine(
        tlsPort: Int,
        timeouts: ProbeTimeouts = ProbeTimeouts(handshakeMs = 5_000, firstDataMs = 3_000),
    ): Int {
        val e = ProbeEngine(
            scope, onEvent = { events += it }, onPlaintext = { h, c, b -> plaintexts += Triple(h, c, b) },
            timeouts = timeouts, tlsPorts = setOf(tlsPort),
        )
        engine = e
        return e.start()
    }

    /** Opens a connection to the engine and completes the SOCKS5 greeting and RFC 1929 auth. */
    private fun socksAuthed(proxyPort: Int): Socket {
        val s = Socket("127.0.0.1", proxyPort).also { closeables += it; it.soTimeout = 10_000 }
        val out = s.getOutputStream()
        val inp = DataInputStream(s.getInputStream())
        out.write(byteArrayOf(5, 1, 2))
        ByteArray(2).also(inp::readFully)
        val c = engine!!.credentials
        val u = c.username.toByteArray()
        val p = c.password.toByteArray()
        out.write(byteArrayOf(1, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p)
        assertEquals(0, ByteArray(2).also(inp::readFully)[1].toInt())
        return s
    }

    /** SOCKS5 CONNECT to 127.0.0.1:[dstPort] through the engine; returns the tunnelled raw socket. */
    private fun socksConnect(proxyPort: Int, dstPort: Int): Socket {
        val s = socksAuthed(proxyPort)
        s.getOutputStream().write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, (dstPort shr 8).toByte(), dstPort.toByte()))
        assertEquals(0, ByteArray(10).also(DataInputStream(s.getInputStream())::readFully)[1].toInt())
        return s
    }

    /** The bytes of a real TLS ClientHello carrying [sni]. */
    private fun clientHello(sni: String): ByteArray {
        val engine = SSLContext.getDefault().createSSLEngine().apply {
            useClientMode = true
            sslParameters = sslParameters.apply { serverNames = listOf(SNIHostName(sni)) }
        }
        engine.beginHandshake()
        val out = ByteBuffer.allocate(engine.session.packetBufferSize)
        engine.wrap(ByteBuffer.allocate(0), out)
        return out.array().copyOf(out.position())
    }

    private fun tlsClient(
        proxyPort: Int, dstPort: Int, sni: String?, trust: X509TrustManager?,
    ): SSLSocket {
        val raw = socksConnect(proxyPort, dstPort)
        val ctx = SSLContext.getInstance("TLS").apply { init(null, trust?.let { arrayOf(it) }, null) }
        val ssl = ctx.socketFactory.createSocket(raw, sni ?: "127.0.0.1", dstPort, true) as SSLSocket
        ssl.soTimeout = 10_000
        if (sni != null) ssl.sslParameters = ssl.sslParameters.apply { serverNames = listOf(SNIHostName(sni)) }
        return ssl
    }

    /** One request/response; returns the body read, or null when the handshake or exchange failed. */
    private fun request(ssl: SSLSocket, header: String = "X-Test: 1"): String? = runCatching {
        ssl.use {
            it.startHandshake()
            it.outputStream.write("GET / HTTP/1.1\r\nHost: a.test\r\n$header\r\n\r\n".toByteArray())
            it.outputStream.flush()
            String(it.inputStream.readBytes())
        }
    }.getOrNull()

    private fun nextEvent(): EngineEvent =
        events.poll(10, TimeUnit.SECONDS) ?: error("no event within 10 s")

    @Test
    fun vulnerableClientGetsT2ThenT3ThenForward() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)

        request(tlsClient(proxy, upstream, "Vuln.Example.test", trustAll))
        val e1 = nextEvent() as EngineEvent.Probed
        request(tlsClient(proxy, upstream, "vuln.example.test", trustAll))
        val e2 = nextEvent() as EngineEvent.Probed
        val body = request(tlsClient(proxy, upstream, "vuln.example.test", trustAll))
        val e3 = nextEvent() as EngineEvent.Forwarded

        assertEquals("vuln.example.test", e1.host)
        assertEquals(ProbeCase.T2_UNTRUSTED_CA, e1.result.case)
        assertEquals(OutcomeKind.ACCEPTED, e1.result.kind)
        assertEquals(ProbeCase.T3_WRONG_HOST, e2.result.case)
        assertEquals(OutcomeKind.ACCEPTED, e2.result.kind)
        assertEquals(ForwardReason.HOST_DONE, e3.reason)
        assertEquals("vuln.example.test", e3.host)
        assertEquals(String(UPSTREAM_REPLY), body)
    }

    @Test
    fun correctClientGetsT2ThenT1() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)

        assertNull(request(tlsClient(proxy, upstream, "good.example.test", null)))
        val e1 = nextEvent() as EngineEvent.Probed
        assertNull(request(tlsClient(proxy, upstream, "good.example.test", null)))
        val e2 = nextEvent() as EngineEvent.Probed

        assertEquals(ProbeCase.T2_UNTRUSTED_CA, e1.result.case)
        assertEquals(OutcomeKind.REJECTED, e1.result.kind)
        assertEquals(ProbeCase.T1_SELF_SIGNED, e2.result.case)
        assertEquals(OutcomeKind.REJECTED, e2.result.kind)
    }

    @Test
    fun noSniIsForwardedAndReported() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)

        val body = request(tlsClient(proxy, upstream, sni = null, trust = trustAll))
        val e = nextEvent() as EngineEvent.Forwarded

        assertEquals(ForwardReason.NO_SNI, e.reason)
        assertEquals("127.0.0.1:$upstream", e.host)
        assertEquals(String(UPSTREAM_REPLY), body)
    }

    @Test
    fun plaintextCallbackGetsUnredactedBytes() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)
        val secret = "supersecretvalue12345"

        request(tlsClient(proxy, upstream, "leak.example.test", trustAll), header = "X-Token: $secret")
        val e = nextEvent() as EngineEvent.Probed

        val (host, case, bytes) = plaintexts.single()
        assertEquals("leak.example.test", host)
        assertEquals(ProbeCase.T2_UNTRUSTED_CA, case)
        assertTrue(String(bytes).contains(secret))
        val evidence = e.result.evidence!!
        val token = evidence.headers.single { it.name.equals("X-Token", ignoreCase = true) }
        assertFalse(token.preview.contains(secret))
        assertEquals(secret.length, token.length)
    }

    @Test
    fun otherPortIsForwardedWithOneEventPerDestination() {
        val tlsPort = startUpstream()
        val proxy = startEngine(tlsPort)
        val echo = ServerSocket(0, 50, InetAddress.getLoopbackAddress()).also { closeables += it }
        thread(isDaemon = true) {
            while (!echo.isClosed) {
                val s = runCatching { echo.accept() }.getOrNull() ?: break
                thread(isDaemon = true) {
                    runCatching { s.use { it.getOutputStream().write(it.getInputStream().read()) } }
                }
            }
        }

        repeat(2) {
            val s = socksConnect(proxy, echo.localPort)
            s.getOutputStream().write(42)
            assertEquals(42, s.getInputStream().read())
            s.close()
        }
        val e = nextEvent() as EngineEvent.Forwarded

        assertEquals(ForwardReason.NON_TLS_PORT, e.reason)
        assertEquals("127.0.0.1:${echo.localPort}", e.host)
        assertNull(events.poll(500, TimeUnit.MILLISECONDS))
    }

    /** A raw upstream that reads until EOF, records everything, and echoes it back. */
    private fun startEchoToEof(received: LinkedBlockingQueue<ByteArray>? = null): ServerSocket {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress()).also { closeables += it }
        thread(isDaemon = true) {
            runCatching {
                server.accept().use { s ->
                    val all = s.getInputStream().readBytes()
                    received?.add(all)
                    s.getOutputStream().write(all)
                }
            }
        }
        return server
    }

    @Test
    fun nonTlsBytesOnTlsPortAreForwardedWithTheExactPrefix() {
        val upstream = startEchoToEof()
        val proxy = startEngine(upstream.localPort)
        val part1 = "GET / HT".toByteArray()
        val part2 = "TP/1.1\r\nHost: x\r\n\r\n".toByteArray()

        val s = socksConnect(proxy, upstream.localPort)
        s.getOutputStream().write(part1)
        s.getOutputStream().flush()
        Thread.sleep(150)
        s.getOutputStream().write(part2)
        s.shutdownOutput()
        val echoed = s.getInputStream().readBytes()
        val e = nextEvent() as EngineEvent.Forwarded

        assertEquals(String(part1 + part2), String(echoed))
        assertEquals(ForwardReason.NOT_TLS, e.reason)
    }

    @Test
    fun partialTlsBytesThenEofAreForwardedAsNotTls() {
        val received = LinkedBlockingQueue<ByteArray>()
        val upstream = startEchoToEof(received)
        val proxy = startEngine(upstream.localPort)
        val partial = byteArrayOf(0x16, 0x03, 0x01, 0x00)

        val s = socksConnect(proxy, upstream.localPort)
        s.getOutputStream().write(partial)
        s.shutdownOutput()
        val e = nextEvent() as EngineEvent.Forwarded

        assertEquals(ForwardReason.NOT_TLS, e.reason)
        assertEquals(partial.toList(), received.poll(10, TimeUnit.SECONDS)!!.toList())
    }

    @Test
    fun silentClientWithZeroBytesIsClosedWithoutAnEvent() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream, ProbeTimeouts(handshakeMs = 300, firstDataMs = 300))

        val s = socksConnect(proxy, upstream)

        assertEquals(-1, s.getInputStream().read())
        assertNull(events.poll(500, TimeUnit.MILLISECONDS))
    }

    @Test
    fun timeoutsAreReportedOnceEachThenHostIsForwarded() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream, ProbeTimeouts(handshakeMs = 300, firstDataMs = 300))
        val hello = clientHello("slow.example.test")

        repeat(2) {
            val s = socksConnect(proxy, upstream)
            s.getOutputStream().write(hello)
            s.getOutputStream().flush()
            val e = nextEvent() as EngineEvent.Probed
            assertEquals("slow.example.test", e.host)
            assertEquals(ProbeCase.T2_UNTRUSTED_CA, e.result.case)
            assertEquals(OutcomeKind.TIMEOUT, e.result.kind)
            s.close()
        }
        val body = request(tlsClient(proxy, upstream, "slow.example.test", trustAll))
        val e3 = nextEvent() as EngineEvent.Forwarded

        assertEquals(ForwardReason.HOST_DONE, e3.reason)
        assertEquals(String(UPSTREAM_REPLY), body)
    }

    @Test
    fun stopDuringHandshakeDeliversNothingNew() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)
        val s = socksConnect(proxy, upstream)
        s.getOutputStream().write(clientHello("stop.example.test"))
        s.getOutputStream().flush()
        Thread.sleep(500) // the probe is now waiting for the client's handshake reply

        engine!!.stop()

        assertNull(events.poll(1, TimeUnit.SECONDS))
        assertTrue(plaintexts.isEmpty())
    }

    @Test
    fun probeFinishingAfterStopBeganIsNotReported() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)
        val s = socksConnect(proxy, upstream)
        s.getOutputStream().write(clientHello("late.example.test"))
        s.getOutputStream().flush()
        // Our flight (ServerHello + bad certificate) arrives: the probe now waits for the client.
        s.soTimeout = 5_000
        assertTrue(s.getInputStream().read(ByteArray(1024)) > 0)

        engine!!.stop()
        s.close() // the peer's EOF, as when the tunnel closes its side after stop() began

        assertNull(events.poll(1, TimeUnit.SECONDS))
        assertTrue(plaintexts.isEmpty())
    }

    @Test
    fun hostDoneIsReportedOncePerHost() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)
        repeat(2) {
            request(tlsClient(proxy, upstream, "done.example.test", trustAll))
            assertTrue(nextEvent() is EngineEvent.Probed)
        }

        repeat(3) {
            assertEquals(String(UPSTREAM_REPLY), request(tlsClient(proxy, upstream, "done.example.test", trustAll)))
        }
        val e = nextEvent() as EngineEvent.Forwarded

        assertEquals(ForwardReason.HOST_DONE, e.reason)
        assertNull(events.poll(500, TimeUnit.MILLISECONDS))
    }

    @Test
    fun noSniIsReportedOncePerDestination() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)

        repeat(2) {
            assertEquals(String(UPSTREAM_REPLY), request(tlsClient(proxy, upstream, sni = null, trust = trustAll)))
        }
        val e = nextEvent() as EngineEvent.Forwarded

        assertEquals(ForwardReason.NO_SNI, e.reason)
        assertNull(events.poll(500, TimeUnit.MILLISECONDS))
    }

    @Test
    fun notTlsIsReportedOncePerDestination() {
        val upstream = ServerSocket(0, 50, InetAddress.getLoopbackAddress()).also { closeables += it }
        thread(isDaemon = true) {
            while (!upstream.isClosed) {
                val c = runCatching { upstream.accept() }.getOrNull() ?: break
                thread(isDaemon = true) { runCatching { c.use { it.getInputStream().readBytes() } } }
            }
        }
        val proxy = startEngine(upstream.localPort)

        repeat(2) {
            val s = socksConnect(proxy, upstream.localPort)
            s.getOutputStream().write("GET / HTTP/1.1\r\nHost: x\r\n\r\n".toByteArray())
            s.shutdownOutput()
            s.getInputStream().readBytes()
            s.close()
        }
        val e = nextEvent() as EngineEvent.Forwarded

        assertEquals(ForwardReason.NOT_TLS, e.reason)
        assertNull(events.poll(500, TimeUnit.MILLISECONDS))
    }

    @Test
    fun udpToQuicPortIsDroppedOncePerDestination() {
        val proxy = startEngine(tlsPort = 4433)
        val ctl = socksAuthed(proxy)
        val out = ctl.getOutputStream()
        val inp = DataInputStream(ctl.getInputStream())
        out.write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
        val rep = ByteArray(10).also(inp::readFully)
        val relayPort = ((rep[8].toInt() and 0xFF) shl 8) or (rep[9].toInt() and 0xFF)
        val udp = java.net.DatagramSocket().also { closeables += AutoCloseable { it.close() } }
        val packet = byteArrayOf(0, 0, 0, 1, 10, 0, 0, 1, (4433 shr 8).toByte(), 4433.toByte(), 1, 2, 3)

        repeat(2) {
            udp.send(java.net.DatagramPacket(packet, packet.size, InetAddress.getByName("127.0.0.1"), relayPort))
        }
        val e = nextEvent() as EngineEvent.QuicDropped

        assertEquals("10.0.0.1:4433", e.host)
        assertNull(events.poll(500, TimeUnit.MILLISECONDS))
    }

    @Test
    fun throwingCallbacksDoNotBreakConnections() {
        val upstream = startUpstream()
        val e = ProbeEngine(
            scope,
            onEvent = { events += it; error("boom") },
            onPlaintext = { h, c, b -> plaintexts += Triple(h, c, b); error("boom") },
            tlsPorts = setOf(upstream),
        ).also { engine = it }
        val proxy = e.start()

        repeat(2) {
            request(tlsClient(proxy, upstream, "boom.example.test", trustAll))
            assertTrue(nextEvent() is EngineEvent.Probed)
        }
        val third = request(tlsClient(proxy, upstream, "boom.example.test", trustAll))

        assertEquals(String(UPSTREAM_REPLY), third)
        assertEquals(2, plaintexts.size)
    }

    @Test
    fun stopIsIdempotentAndSilencesEvents() {
        val upstream = startUpstream()
        val proxy = startEngine(upstream)
        engine!!.stop()
        engine!!.stop()

        assertTrue(runCatching { socksConnect(proxy, upstream) }.isFailure)
        assertNull(events.poll(300, TimeUnit.MILLISECONDS))
    }

    private companion object {
        val UPSTREAM_REPLY = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".toByteArray()
    }
}
