package io.github.leemikepop.trustprobe.core.tls

import java.nio.ByteBuffer
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ClientHelloParserTest {

    private fun clientHello(withSni: Boolean = true): ByteArray {
        val engine: SSLEngine = SSLContext.getDefault().createSSLEngine()
        engine.useClientMode = true
        val params = engine.sslParameters
        if (withSni) params.serverNames = listOf(SNIHostName("api.example.com"))
        params.applicationProtocols = arrayOf("h2", "http/1.1")
        engine.sslParameters = params
        val out = ByteBuffer.allocate(engine.session.packetBufferSize)
        engine.wrap(ByteBuffer.allocate(0), out)
        out.flip()
        return ByteArray(out.remaining()).also { out.get(it) }
    }

    private fun record(payload: ByteArray, from: Int = 0, to: Int = payload.size): ByteArray {
        val n = to - from
        return byteArrayOf(22, 3, 3, (n shr 8).toByte(), n.toByte()) + payload.copyOfRange(from, to)
    }

    @Test
    fun parsesSniAndAlpn() {
        val bytes = clientHello()
        val r = ClientHelloParser.parse(bytes, bytes.size)
        assertEquals(ClientHelloResult.Complete("api.example.com", listOf("h2", "http/1.1"), bytes.size), r)
    }

    @Test
    fun parsesWhenSplitAcrossReads() {
        val bytes = clientHello()
        for (n in listOf(1, 5, 100, bytes.size - 1)) {
            assertEquals("n=$n", ClientHelloResult.NeedMore, ClientHelloParser.parse(bytes, n))
        }
        assertTrue(ClientHelloParser.parse(bytes, bytes.size) is ClientHelloResult.Complete)
    }

    @Test
    fun parsesWhenSplitAcrossRecords() {
        val bytes = clientHello()
        val payload = bytes.copyOfRange(5, bytes.size)
        val half = payload.size / 2
        val split = record(payload, 0, half) + record(payload, half, payload.size)
        val r = ClientHelloParser.parse(split, split.size)
        assertEquals(ClientHelloResult.Complete("api.example.com", listOf("h2", "http/1.1"), split.size), r)
        assertEquals(ClientHelloResult.NeedMore, ClientHelloParser.parse(split, split.size - 1))
        assertEquals(ClientHelloResult.NeedMore, ClientHelloParser.parse(split, 5 + half))
    }

    @Test
    fun ignoresBytesAfterTheClientHello() {
        val bytes = clientHello()
        val padded = bytes + byteArrayOf(1, 2, 3, 4, 5, 6)
        val r = ClientHelloParser.parse(padded, padded.size) as ClientHelloResult.Complete
        assertEquals(bytes.size, r.consumedLength)
    }

    @Test
    fun noSniExtension() {
        val bytes = clientHello(withSni = false)
        val r = ClientHelloParser.parse(bytes, bytes.size) as ClientHelloResult.Complete
        assertEquals(null, r.sni)
        assertEquals(listOf("h2", "http/1.1"), r.alpn)
    }

    @Test
    fun rejectsNonTls() {
        val http = "GET / HTTP/1.1\r\n".toByteArray()
        assertTrue(ClientHelloParser.parse(http, http.size) is ClientHelloResult.NotTls)
        assertTrue(ClientHelloParser.parse(http, 1) is ClientHelloResult.NotTls)
    }

    @Test
    fun rejectsNonHandshakeRecordAfterHandshakeRecord() {
        val bytes = clientHello()
        val payload = bytes.copyOfRange(5, bytes.size)
        val second = record(payload, 0, 10)
        val bad = second + byteArrayOf(23, 3, 3, 0, 1, 0)
        assertTrue(ClientHelloParser.parse(bad, bad.size) is ClientHelloResult.NotTls)
    }

    @Test
    fun rejectsTruncatedLengthFields() {
        val body = ByteBuffer.allocate(200).apply {
            put(3).put(3)                       // client_version
            put(ByteArray(32))                  // random
            put(0)                              // session id length
            putShort(2).putShort(0x1301)        // cipher suites
            put(1).put(0)                       // compression
            putShort(8)                         // extensions length
            putShort(0).putShort(0xFFFF.toShort()) // SNI ext claiming 65535 bytes
        }.let { it.array().copyOf(it.position()) }
        val hs = byteArrayOf(1, 0, (body.size shr 8).toByte(), body.size.toByte()) + body
        val rec = record(hs)
        assertTrue(ClientHelloParser.parse(rec, rec.size) is ClientHelloResult.NotTls)
    }

    @Test
    fun usesOnlyFirstLenBytes() {
        val bytes = clientHello()
        val padded = bytes + ByteArray(50)
        assertEquals(ClientHelloResult.NeedMore, ClientHelloParser.parse(padded, 100))
    }
}
