package io.github.leemikepop.trustprobe.core.evidence

import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

@Serializable
data class RedactedHeader(val name: String, val preview: String, val length: Int)

@Serializable
data class RequestEvidence(
    val protocol: String, // "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "UNKNOWN"
    val method: String?,
    val host: String?,
    val path: String?,
    val headers: List<RedactedHeader>,
    val firstRecordBytes: Int,
)

/** Turns the decrypted first request bytes into masked evidence. Never throws. */
object RequestEvidenceParser {
    private const val MAX_INPUT = 8 * 1024
    private const val MAX_HEADERS = 64
    private const val MAX_NAME = 64
    private const val H2_PREFACE = "PRI * HTTP/2.0"
    private val HOST = Regex("(?:[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*|\\[[0-9A-Fa-f:.]+])(?::[0-9]{1,5})?")
    private val METHOD = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")

    fun parse(plaintext: ByteArray): RequestEvidence {
        val size = plaintext.size
        val unknown = RequestEvidence("UNKNOWN", null, null, null, emptyList(), size)
        val text = String(plaintext, 0, minOf(size, MAX_INPUT), Charsets.ISO_8859_1)
        if (text.startsWith(H2_PREFACE)) return unknown.copy(protocol = "HTTP/2")

        val lines = text.split('\n').map { it.removeSuffix("\r") }
        if (lines.size < 2) return unknown // no complete line
        val complete = lines.dropLast(1) // last element is a truncated or empty remainder

        val requestLine = complete[0]
        if (requestLine.any(::isControl)) return unknown
        val parts = requestLine.split(' ')
        if (parts.size != 3 || !METHOD.matches(parts[0]) || parts[2] !in setOf("HTTP/1.0", "HTTP/1.1")) return unknown
        val target = parts[1]
        val validTarget = target == "*" || target.startsWith("/") ||
            target.startsWith("http://") || target.startsWith("https://")
        if (!validTarget) return unknown

        val headers = mutableListOf<RedactedHeader>()
        var host: String? = null
        for (line in complete.drop(1)) {
            if (line.isEmpty()) break
            if (headers.size >= MAX_HEADERS) break
            if (line[0] == ' ' || line[0] == '\t') continue // obs-fold continuation
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val name = line.substring(0, colon)
            if (name.length > MAX_NAME || !METHOD.matches(name)) continue
            val value = decodeValue(line.substring(colon + 1).trim { it == ' ' || it == '\t' })
            if (host == null && name.equals("Host", ignoreCase = true) && validHost(value)) host = value
            headers += RedactedHeader(name, Redactor.value(value), value.codePointCount(0, value.length))
        }
        return RequestEvidence(parts[2], parts[0], host, Redactor.path(target), headers, size)
    }

    private fun isControl(c: Char) = c < ' ' || c == '\u007F'

    private fun validHost(v: String): Boolean = v.length <= 255 && HOST.matches(v)

    /** Header bytes were decoded as ISO-8859-1; re-decode as UTF-8 only when they are valid UTF-8. */
    private fun decodeValue(latin1: String): String {
        val bytes = latin1.toByteArray(Charsets.ISO_8859_1)
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            latin1
        }
    }
}
