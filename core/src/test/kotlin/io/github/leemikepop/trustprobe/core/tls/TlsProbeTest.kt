package io.github.leemikepop.trustprobe.core.tls

import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import io.github.leemikepop.trustprobe.core.probe.RejectStage
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit.SECONDS
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsProbeTest {
    private val certs = CertificateFactory()
    private val pool = Executors.newCachedThreadPool()
    private val closeables = mutableListOf<AutoCloseable>()

    @After
    fun tearDown() {
        closeables.forEach { runCatching { it.close() } }
        pool.shutdownNow()
    }

    private class Run<T>(val result: ProbeResult, val plaintext: ByteArray?, val client: T)

    /** Runs [client] against a probe on separate threads, each with a hard timeout. */
    private fun <T> probe(
        case: ProbeCase = ProbeCase.T2_UNTRUSTED_CA,
        timeouts: ProbeTimeouts = ProbeTimeouts(),
        sni: String? = null,
        client: (port: Int) -> T,
    ): Run<T> {
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).also { closeables += it }
        val serverSide = pool.submit<Pair<ProbeResult, ByteArray?>> {
            val socket = server.accept()
            val (initial, parsedSni) = readClientHello(socket)
            TlsProbe(certs, timeouts).run(socket, initial, sni ?: parsedSni!!, case).also {
                assertTrue("run must close the client socket", socket.isClosed)
            }
        }
        val clientSide = pool.submit<T> { client(server.localPort) }
        val (result, plaintext) = serverSide.get(15, SECONDS)
        return Run(result, plaintext, clientSide.get(15, SECONDS))
    }

    private fun readClientHello(socket: Socket): Pair<ByteArray, String?> {
        socket.soTimeout = 5_000
        val buf = ByteArray(64 * 1024)
        var len = 0
        while (true) {
            val n = socket.getInputStream().read(buf, len, buf.size - len)
            check(n > 0) { "client closed before sending a ClientHello" }
            len += n
            when (val r = ClientHelloParser.parse(buf, len)) {
                is ClientHelloResult.Complete -> return buf.copyOf(len) to r.sni
                ClientHelloResult.NeedMore -> continue
                is ClientHelloResult.NotTls -> error(r.reason)
            }
        }
    }

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    /** A JDK TLS client; [trust] null means the JDK default trust store (trusts none of our certs). */
    private fun connect(
        port: Int,
        trust: X509TrustManager?,
        protocol: String? = null,
        alpn: List<String>? = null,
        suites: List<String>? = null,
    ): SSLSocket {
        val context = SSLContext.getInstance("TLS").apply { init(null, trust?.let { arrayOf(it) }, null) }
        val raw = Socket(InetAddress.getLoopbackAddress(), port)
        val ssl = context.socketFactory.createSocket(raw, HOST, port, true) as SSLSocket
        ssl.soTimeout = 10_000
        ssl.sslParameters = ssl.sslParameters.apply {
            serverNames = listOf(SNIHostName(HOST))
            protocol?.let { protocols = arrayOf(it) }
            alpn?.let { applicationProtocols = it.toTypedArray() }
            suites?.let { cipherSuites = it.toTypedArray() }
        }
        return ssl
    }

    /** Reads until the probe closes the connection. */
    private fun drain(s: SSLSocket) {
        runCatching { while (s.inputStream.read() >= 0) Unit }
    }

    private fun sendRequestAndDrain(s: SSLSocket) {
        s.startHandshake()
        s.outputStream.write(REQUEST)
        s.outputStream.flush()
        drain(s)
    }

    @Test
    fun trustAllClientIsAccepted() {
        val run = probe { port -> connect(port, trustAll).use(::sendRequestAndDrain) }

        assertEquals(OutcomeKind.ACCEPTED, run.result.kind)
        assertNull(run.result.rejectStage)
        assertEquals(ProbeCase.T2_UNTRUSTED_CA, run.result.case)
        assertEquals("GET", run.result.evidence?.method)
        assertEquals(HOST, run.result.evidence?.host)
        assertArrayEquals(REQUEST, run.plaintext)
    }

    @Test
    fun defaultClientIsRejected() {
        for (case in ProbeCase.entries) {
            val run = probe(case) { port ->
                connect(port, trust = null).use { runCatching { it.startHandshake() }.exceptionOrNull() }
            }

            assertEquals(case.name, OutcomeKind.REJECTED, run.result.kind)
            assertEquals(case.name, RejectStage.ALERT_OR_CLOSE_DURING_HANDSHAKE, run.result.rejectStage)
            assertNull(case.name, run.result.tlsVersion)
            assertNull(case.name, run.plaintext)
            assertNotNull("client must have failed the handshake for $case", run.client)
        }
    }

    @Test
    fun closeAfterHandshakeIsRejected() {
        // TLS 1.2 here; TLS 1.3 is postHandshakeTicketIsNotData.
        val run = probe { port ->
            connect(port, trustAll, protocol = "TLSv1.2").use { it.startHandshake() }
        }

        assertEquals(OutcomeKind.REJECTED, run.result.kind)
        assertEquals(RejectStage.CLOSED_AFTER_HANDSHAKE, run.result.rejectStage)
        assertEquals("TLSv1.2", run.result.tlsVersion)
        assertNull(run.plaintext)
    }

    @Test
    fun postHandshakeTicketIsNotData() {
        val run = probe { port ->
            connect(port, trustAll, protocol = "TLSv1.3").use { it.startHandshake() }
        }

        assertEquals(OutcomeKind.REJECTED, run.result.kind)
        assertEquals(RejectStage.CLOSED_AFTER_HANDSHAKE, run.result.rejectStage)
        assertEquals("TLSv1.3", run.result.tlsVersion)
        assertNull(run.result.evidence)
        assertNull(run.plaintext)
    }

    @Test
    fun silentClientTimesOut() {
        val run = probe(timeouts = ProbeTimeouts(handshakeMs = 500)) { port ->
            Socket(InetAddress.getLoopbackAddress(), port).use { s ->
                s.soTimeout = 10_000
                s.getOutputStream().write(clientHello())
                runCatching { while (s.getInputStream().read() >= 0) Unit }
            }
        }

        assertEquals(OutcomeKind.TIMEOUT, run.result.kind)
        assertNull(run.result.rejectStage)
        assertNull(run.result.tlsVersion)
        assertTrue("took ${run.result.durationMs} ms", run.result.durationMs in 450L..10_000L)
    }

    @Test
    fun silentAfterHandshakeTimesOut() {
        val run = probe(timeouts = ProbeTimeouts(firstDataMs = 300)) { port ->
            connect(port, trustAll).use { it.startHandshake(); drain(it) }
        }

        assertEquals(OutcomeKind.TIMEOUT, run.result.kind)
        assertNull(run.result.rejectStage)
        assertNotNull(run.result.tlsVersion)
        assertNull(run.plaintext)
    }

    @Test
    fun selectsHttp11Alpn() {
        val run = probe { port ->
            connect(port, trustAll, alpn = listOf("h2", "http/1.1")).use {
                it.startHandshake()
                it.applicationProtocol
            }
        }

        assertEquals("http/1.1", run.client)
    }

    @Test
    fun withoutHttp11NoAlpnIsSelected() {
        val run = probe { port ->
            connect(port, trustAll, alpn = listOf("h2")).use {
                it.startHandshake()
                it.applicationProtocol
            }
        }

        assertEquals("", run.client)
        assertEquals(RejectStage.CLOSED_AFTER_HANDSHAKE, run.result.rejectStage)
    }

    @Test
    fun tls12AndTls13BothWork() {
        for (version in listOf("TLSv1.2", "TLSv1.3")) {
            val run = probe { port -> connect(port, trustAll, protocol = version).use(::sendRequestAndDrain) }

            assertEquals(version, OutcomeKind.ACCEPTED, run.result.kind)
            assertEquals(version, run.result.tlsVersion)
            assertArrayEquals(version, REQUEST, run.plaintext)
        }
    }

    @Test
    fun badSniGivesError() {
        val run = probe(sni = " ") { port ->
            connect(port, trustAll).use { runCatching { it.startHandshake() }.exceptionOrNull() }
        }

        assertEquals(OutcomeKind.ERROR, run.result.kind)
        assertNull(run.result.rejectStage)
        assertEquals("blank SNI", run.result.detail)
        assertNull(run.plaintext)
    }

    @Test
    fun localHandshakeFailureIsErrorNotRejection() {
        // Our EC key cannot serve an RSA-only client: the client never sees a certificate.
        val run = probe { port ->
            connect(port, trustAll, protocol = "TLSv1.2", suites = listOf("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
                .use { runCatching { it.startHandshake() }.exceptionOrNull() }
        }

        assertEquals(OutcomeKind.ERROR, run.result.kind)
        assertNull(run.result.rejectStage)
        assertNotNull(run.result.detail)
    }

    /** A real ClientHello, produced by a client engine that is then abandoned. */
    private fun clientHello(): ByteArray {
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), null) }
        val engine = context.createSSLEngine(HOST, 443).apply { useClientMode = true }
        engine.beginHandshake()
        val out = ByteBuffer.allocate(engine.session.packetBufferSize)
        engine.wrap(ByteBuffer.allocate(0), out)
        return out.array().copyOf(out.position())
    }

    private companion object {
        const val HOST = "probe.trustprobe.test"
        val REQUEST = "GET / HTTP/1.1\r\nHost: $HOST\r\nUser-Agent: test\r\n\r\n".toByteArray()
    }
}
