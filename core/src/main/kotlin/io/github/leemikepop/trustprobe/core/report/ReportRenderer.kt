package io.github.leemikepop.trustprobe.core.report

import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.ForwardReason
import io.github.leemikepop.trustprobe.core.evidence.RequestEvidence
import io.github.leemikepop.trustprobe.core.probe.HostVerdict
import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.Verdict
import kotlinx.serialization.json.Json
import java.time.Instant

object ReportRenderer {
    private val JSON = Json { prettyPrint = true; encodeDefaults = true }

    fun json(r: Report): String = JSON.encodeToString(Report.serializer(), r)

    fun markdown(r: Report): String = buildString {
        appendLine("# TrustProbe report: ${md(r.appLabel)}")
        appendLine()
        val seconds = maxOf(0L, r.endedAt - r.startedAt) / 1000
        val vulnerable = r.hosts.count { it.verdict == Verdict.VULNERABLE }
        val inconclusive = r.hosts.count { it.verdict == Verdict.INCONCLUSIVE }
        val verdict = r.appVerdict.name + (r.appReason?.let { " (${it.name})" } ?: "")
        appendLine(
            "Package ${md(r.packageName)}: **$verdict**, $vulnerable of ${r.hosts.size} hosts vulnerable, $inconclusive inconclusive. " +
                "Started ${iso(r.startedAt)}, ended ${iso(r.endedAt)} (${seconds}s).",
        )
        appendLine()
        appendLine("| Host | Verdict | Severity / reason | Cases run | Notes |")
        appendLine("| --- | --- | --- | --- | --- |")
        for (h in r.hosts) {
            val detail = h.severity?.name ?: h.reason?.name ?: ""
            val notes = listOfNotNull(
                "self-signed untested".takeIf { h.selfSignedUntested },
                "hostname untested".takeIf { h.hostnameUntested },
                CLOSED_AFTER_HANDSHAKE_NOTE.takeIf { h.closedAfterHandshake },
            ).joinToString(", ")
            appendLine(
                "| ${md(h.host)} | ${h.verdict.name} | $detail | " +
                    "${h.casesRun.joinToString(", ") { it.name }} | $notes |",
            )
        }
        val withVerdict = r.hosts.map { it.host }.toSet()
        val notTls = r.events.filter {
            it is EngineEvent.Forwarded && (it.reason == ForwardReason.NOT_TLS || it.reason == ForwardReason.NON_TLS_PORT)
        }.map { it.host }.filter { it !in withVerdict }.distinct().size
        val quic = r.events.filterIsInstance<EngineEvent.QuicDropped>()
            .map { it.host }.filter { it !in withVerdict }.distinct().size
        if (notTls > 0 || quic > 0) {
            appendLine()
            appendLine("Not tested: $notTls non-TLS connections, $quic QUIC flows dropped")
        }
        val evidence = r.hosts.filter { it.verdict == Verdict.VULNERABLE }
            .mapNotNull { h -> evidenceOf(r, h)?.let { h to it } }
        if (evidence.isNotEmpty()) {
            appendLine()
            appendLine("## Evidence")
            for ((h, e) in evidence) {
                appendLine()
                appendLine("### ${md(h.host)}")
                appendLine()
                appendLine("- Protocol: ${md(e.protocol)}")
                appendLine("- Method: ${md(e.method ?: "-")}")
                appendLine("- Host: ${md(e.host ?: "-")}")
                appendLine("- Path: ${md(e.path ?: "-")}")
                if (e.headers.isEmpty()) {
                    appendLine("- Headers: none")
                } else {
                    appendLine("- Headers (masked):")
                    for (hd in e.headers) appendLine("  - ${md(hd.name)}: ${md(hd.preview)} (length ${hd.length})")
                }
            }
        }
    }

    /** [Report.events] is already sorted by time, so the first match is the earliest. */
    private fun evidenceOf(r: Report, h: HostVerdict): RequestEvidence? = r.events
        .filterIsInstance<EngineEvent.Probed>()
        .firstOrNull { it.host == h.host && it.result.kind == OutcomeKind.ACCEPTED && it.result.evidence != null }
        ?.result?.evidence

    private fun iso(ms: Long) = Instant.ofEpochMilli(ms).toString().let {
        if (it.length > 20 && it.endsWith("Z") && it.contains('.')) it.substringBefore('.') + "Z" else it
    }

    /** Also shown on the report screen; kept in one place so the two read the same. */
    const val CLOSED_AFTER_HANDSHAKE_NOTE =
        "handshake completed, then closed without sending data (post-handshake check such as pinning, or an idle close)"

    private const val MD_SPECIAL = "`*_[]#~|!()"

    /** The one escaper for every network- or app-controlled string placed into the Markdown. */
    private fun md(s: String): String = buildString {
        for (c in s) {
            when {
                c < ' ' || c.code == 0x7F || c.code == 0x85 || c.code == 0x2028 || c.code == 0x2029 -> append(' ')
                c == '\\' || c in MD_SPECIAL -> append('\\').append(c)
                c == '&' -> append("&amp;")
                c == '<' -> append("&lt;")
                c == '>' -> append("&gt;")
                else -> append(c)
            }
        }
    }
}
