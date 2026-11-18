package io.github.leemikepop.trustprobe.core.evidence

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RequestEvidenceTest {
    private fun parse(s: String) = RequestEvidenceParser.parse(s.toByteArray(Charsets.ISO_8859_1))

    @Test
    fun parsesHttp11Request() {
        val raw = "GET /a?token=abcdefgh HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer xyz123456\r\n\r\n"
        val e = parse(raw)
        assertEquals("HTTP/1.1", e.protocol)
        assertEquals("GET", e.method)
        assertEquals("api.example.com", e.host)
        assertEquals("/a?token=abcd…", e.path)
        assertTrue(e.headers.contains(RedactedHeader("Authorization", "Bear…", 16)))
        assertTrue(e.headers.contains(RedactedHeader("Host", "api.…", 15)))
        assertEquals(raw.length, e.firstRecordBytes)
    }

    @Test
    fun detectsHttp2Preface() {
        val e = parse("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        assertEquals("HTTP/2", e.protocol)
        assertNull(e.method)
        assertNull(e.host)
        assertNull(e.path)
        assertTrue(e.headers.isEmpty())
    }

    @Test
    fun unknownBytesGiveUnknown() {
        val e = RequestEvidenceParser.parse(byteArrayOf(0x16, 0x03, 0x01, 0x00))
        assertEquals("UNKNOWN", e.protocol)
        assertNull(e.method)
        assertTrue(e.headers.isEmpty())
        assertEquals(4, e.firstRecordBytes)
        assertEquals("UNKNOWN", RequestEvidenceParser.parse(ByteArray(0)).protocol)
    }

    @Test
    fun hostHeaderIsCaseInsensitiveAndNotRedacted() {
        val e = parse("POST /x HTTP/1.0\r\nhOsT: api.example.com\r\n\r\n")
        assertEquals("HTTP/1.0", e.protocol)
        assertEquals("api.example.com", e.host)
        assertEquals("hOsT", e.headers.single().name)
    }

    @Test
    fun truncatedLastHeaderIsDropped() {
        val e = parse("GET / HTTP/1.1\r\nHost: a.example.com\r\nX-Token: secretsecr")
        assertEquals(listOf("Host"), e.headers.map { it.name })
    }

    @Test
    fun capsHeaderCount() {
        val sb = StringBuilder("GET / HTTP/1.1\r\n")
        repeat(100) { sb.append("H$it: v\r\n") }
        sb.append("\r\n")
        assertEquals(64, parse(sb.toString()).headers.size)
    }

    @Test
    fun utf8HeaderValueIsDecodedBeforeRedaction() {
        val bytes = "GET / HTTP/1.1\r\nX-N: 密碼一二三四五\r\n\r\n".toByteArray(Charsets.UTF_8)
        val h = RequestEvidenceParser.parse(bytes).headers.single()
        assertEquals("密碼一二…", h.preview)
        assertEquals(7, h.length)
    }

    @Test
    fun garbageNeverThrows() {
        parse("GET\r\n\r\n")
        parse("GET / HTTP/9.9\r\n")
        assertEquals("UNKNOWN", parse("GET / HTTP/9.9\r\nHost: a\r\n\r\n").protocol)
    }

    @Test
    fun bareLfRequestParses() {
        val e = parse("GET /a HTTP/1.1\nHost: api.example.com\nX-A: valuevalue\n\n")
        assertEquals("api.example.com", e.host)
        assertEquals(listOf("Host", "X-A"), e.headers.map { it.name })
    }

    @Test
    fun bareLfDoesNotMergeHeaders() {
        val e = parse("GET / HTTP/1.1\r\nX-A: one\nX-B: S3cr3tT0kenValue9999\r\n\r\n")
        assertEquals(listOf("X-A", "X-B"), e.headers.map { it.name })
        assertEquals("S3cr…", e.headers[1].preview)
    }

    @Test
    fun invalidHostBecomesNull() {
        val e = parse("GET / HTTP/1.1\r\nHost: a.example.com S3cr3tT0kenValue9999\r\n\r\n")
        assertNull(e.host)
        assertEquals(1, e.headers.size)
        assertEquals("a.ex…", e.headers[0].preview)
        assertEquals("[::1]:8443", parse("GET / HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n").host)
        assertEquals("10.0.0.1:80", parse("GET / HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n").host)
    }

    @Test
    fun nonTokenHeaderNameIsSkipped() {
        val e = parse("GET / HTTP/1.1\r\nX S3cr3tT0kenValue9999: v\r\nOk: value\r\n\r\n")
        assertEquals(listOf("Ok"), e.headers.map { it.name })
        assertTrue(parse("GET / HTTP/1.1\r\n" + "N".repeat(65) + ": v\r\n\r\n").headers.isEmpty())
    }

    @Test
    fun bareQueryPartIsMasked() {
        assertEquals("/a?S3cr…", parse("GET /a?S3cr3tT0kenValue9999 HTTP/1.1\r\n\r\n").path)
    }

    @Test
    fun controlCharInTargetGivesUnknown() {
        assertEquals("UNKNOWN", parse("GET /a\u0001b HTTP/1.1\r\n\r\n").protocol)
        assertEquals("UNKNOWN", parse("GET example.com:443 HTTP/1.1\r\n\r\n").protocol)
        assertEquals("UNKNOWN", parse("GET foo HTTP/1.1\r\n\r\n").protocol)
    }

    @Test
    fun obsFoldContinuationIsSkipped() {
        val e = parse("GET / HTTP/1.1\r\nX-A: v\r\n S3cr3tT0kenValue9999\r\n\r\n")
        assertEquals(listOf("X-A"), e.headers.map { it.name })
    }

    @Test
    fun hostileInputsNeverLeakSecret() {
        val s = "S3cr3tT0kenValue9999"
        val inputs = listOf(
            "GET /p?$s HTTP/1.1\r\nHost: h.example.com\r\n\r\n",
            "GET /p?k=$s&$s#$s HTTP/1.1\r\n\r\n",
            "GET https://h.example.com/p?a=$s HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: $s evil\r\n\r\n",
            "GET / HTTP/1.1\r\nX $s: v\r\n\r\n",
            "GET / HTTP/1.1\r\nA: x\nB: $s\r\n\r\n",
            "GET / HTTP/1.1\nAuthorization: Bearer $s\n\n",
            "GET / HTTP/1.1\r\nX-A: v\r\n\t$s\r\n\r\n",
            "GET /$s\u0001 HTTP/1.1\r\n\r\n",
            "GET $s:443 HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nX-A: $s",
        )
        for (raw in inputs) {
            val json = Json.encodeToString(parse(raw))
            assertTrue("leak in: $json", !json.contains(s))
        }
    }
}
