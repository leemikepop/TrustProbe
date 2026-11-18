package io.github.leemikepop.trustprobe.core.evidence

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
}
