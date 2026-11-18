package io.github.leemikepop.trustprobe.core.tls

sealed interface ClientHelloResult {
    /** [consumedLength] is the total size of all TLS records that hold the complete ClientHello. */
    data class Complete(val sni: String?, val alpn: List<String>, val consumedLength: Int) : ClientHelloResult
    data object NeedMore : ClientHelloResult
    data class NotTls(val reason: String) : ClientHelloResult
}

/** Reads SNI and ALPN from the first bytes of a TLS connection. Never modifies the buffer. */
object ClientHelloParser {
    private const val HANDSHAKE = 22
    private const val MAX_RECORD_PAYLOAD = 16384
    private const val MAX_HELLO_LENGTH = 1 shl 20

    private class Malformed(message: String) : Exception(message)

    fun parse(buf: ByteArray, len: Int): ClientHelloResult {
        val limit = minOf(len, buf.size)
        val hs = java.io.ByteArrayOutputStream()
        var pos = 0
        while (true) {
            // Record header: type(1) version(2) length(2), validated as soon as each byte is present.
            if (limit - pos < 1) return ClientHelloResult.NeedMore
            if (u8(buf, pos) != HANDSHAKE) return ClientHelloResult.NotTls("not a handshake record")
            if (limit - pos < 2) return ClientHelloResult.NeedMore
            if (u8(buf, pos + 1) != 3) return ClientHelloResult.NotTls("implausible record version")
            if (limit - pos < 3) return ClientHelloResult.NeedMore
            if (u8(buf, pos + 2) > 4) return ClientHelloResult.NotTls("implausible record version")
            if (limit - pos < 5) return ClientHelloResult.NeedMore
            val recLen = (u8(buf, pos + 3) shl 8) or u8(buf, pos + 4)
            if (recLen == 0 || recLen > MAX_RECORD_PAYLOAD) return ClientHelloResult.NotTls("implausible record length")
            if (limit - pos < 5 + recLen) return ClientHelloResult.NeedMore
            hs.write(buf, pos + 5, recLen)
            pos += 5 + recLen

            val data = hs.toByteArray()
            if (data.isNotEmpty() && u8(data, 0) != 1) return ClientHelloResult.NotTls("not a ClientHello")
            if (data.size < 4) continue
            val helloLen = (u8(data, 1) shl 16) or (u8(data, 2) shl 8) or u8(data, 3)
            if (helloLen > MAX_HELLO_LENGTH) return ClientHelloResult.NotTls("implausible ClientHello length")
            if (data.size < 4 + helloLen) continue
            return try {
                parseBody(data, 4, 4 + helloLen, pos)
            } catch (e: Malformed) {
                ClientHelloResult.NotTls(e.message ?: "malformed ClientHello")
            }
        }
    }

    private fun parseBody(d: ByteArray, start: Int, end: Int, consumed: Int): ClientHelloResult {
        var p = start
        fun need(n: Int) { if (n < 0 || p + n > end) throw Malformed("length field exceeds bounds") }
        fun skip(n: Int) { need(n); p += n }
        fun readU8(): Int { need(1); return u8(d, p++) }
        fun readU16(): Int { need(2); val v = (u8(d, p) shl 8) or u8(d, p + 1); p += 2; return v }

        skip(2 + 32)                 // client_version, random
        skip(readU8())               // session id
        skip(readU16())              // cipher suites
        skip(readU8())               // compression methods
        var sni: String? = null
        var alpn: List<String> = emptyList()
        if (p < end) {
            val extTotal = readU16()
            need(extTotal)
            val extEnd = p + extTotal
            while (p < extEnd) {
                if (extEnd - p < 4) throw Malformed("truncated extension header")
                val type = readU16()
                val extLen = readU16()
                if (extLen > extEnd - p) throw Malformed("extension exceeds bounds")
                val bodyEnd = p + extLen
                when (type) {
                    0 -> sni = parseSni(d, p, bodyEnd)
                    16 -> alpn = parseAlpn(d, p, bodyEnd)
                }
                p = bodyEnd
            }
        }
        return ClientHelloResult.Complete(sni, alpn, consumed)
    }

    private fun parseSni(d: ByteArray, start: Int, end: Int): String? {
        var p = start
        if (end - p < 2) throw Malformed("truncated server_name")
        val listEnd = p + 2 + ((u8(d, p) shl 8) or u8(d, p + 1))
        p += 2
        if (listEnd > end) throw Malformed("server_name list exceeds bounds")
        var host: String? = null
        while (p < listEnd) {
            if (listEnd - p < 3) throw Malformed("truncated server_name entry")
            val nameType = u8(d, p)
            val nameLen = (u8(d, p + 1) shl 8) or u8(d, p + 2)
            p += 3
            if (nameLen > listEnd - p) throw Malformed("server_name exceeds bounds")
            if (nameType == 0 && host == null) host = String(d, p, nameLen, Charsets.US_ASCII)
            p += nameLen
        }
        return host
    }

    private fun parseAlpn(d: ByteArray, start: Int, end: Int): List<String> {
        var p = start
        if (end - p < 2) throw Malformed("truncated ALPN")
        val listEnd = p + 2 + ((u8(d, p) shl 8) or u8(d, p + 1))
        p += 2
        if (listEnd > end) throw Malformed("ALPN list exceeds bounds")
        val out = ArrayList<String>()
        while (p < listEnd) {
            val n = u8(d, p++)
            if (n > listEnd - p) throw Malformed("ALPN entry exceeds bounds")
            out += String(d, p, n, Charsets.US_ASCII)
            p += n
        }
        return out
    }

    private fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
}
