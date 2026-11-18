package io.github.leemikepop.trustprobe.core.report

import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.ForwardReason
import io.github.leemikepop.trustprobe.core.probe.HostVerdict
import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.Verdict
import kotlinx.serialization.json.Json
import java.time.Instant

object ReportRenderer {
    private val JSON = Json { prettyPrint = true; encodeDefaults = true }

    fun json(r: Report): String = JSON.encodeToString(Report.serializer(), r)

    fun markdown(r: Report): String = buildString {
        appendLine("# TrustProbe report: ${text(r.appLabel)}")
        appendLine()
        val seconds = (r.endedAt - r.startedAt) / 1000
        val vulnerable = r.hosts.count { it.verdict == Verdict.VULNERABLE }
        val verdict = r.appVerdict.name + (r.appReason?.let { " (${it.name})" } ?: "")
        appendLine(
            "Package `${text(r.packageName)}`: **$verdict**, $vulnerable of ${r.hosts.size} hosts vulnerable. " +
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
            ).joinToString(", ")
            appendLine(
                "| ${cell(h.host)} | ${h.verdict.name} | $detail | " +
                    "${h.casesRun.joinToString(", ") { it.name }} | $notes |",
            )
        }
        val notTls = r.events.filter {
            it is EngineEvent.Forwarded && (it.reason == ForwardReason.NOT_TLS || it.reason == ForwardReason.NON_TLS_PORT)
        }.map { it.host }.distinct().size
        val quic = r.events.filterIsInstance<EngineEvent.QuicDropped>().map { it.host }.distinct().size
        if (notTls > 0 || quic > 0) {
            appendLine()
            appendLine("Not tested: $notTls non-TLS connections, $quic QUIC flows dropped")
        }
        val evidence = r.hosts.filter { it.verdict == Verdict.VULNERABLE }.mapNotNull { h -> evidenceOf(r, h)?.let { h to it } }
        if (evidence.isNotEmpty()) {
            appendLine()
            appendLine("## Evidence")
            for ((h, e) in evidence) {
                appendLine()
                appendLine("### ${cell(h.host)}")
                appendLine()
                appendLine("- Protocol: ${cell(e.protocol)}")
                appendLine("- Method: ${cell(e.method ?: "-")}")
                appendLine("- Host: ${cell(e.host ?: "-")}")
                appendLine("- Path: ${cell(e.path ?: "-")}")
                if (e.headers.isEmpty()) {
                    appendLine("- Headers: none")
                } else {
                    appendLine("- Headers (masked):")
                    for (hd in e.headers) appendLine("  - ${cell(hd.name)}: ${cell(hd.preview)} (length ${hd.length})")
                }
            }
        }
    }

    private fun evidenceOf(r: Report, h: HostVerdict) = r.events.sortedBy { it.atMillis }
        .filterIsInstance<EngineEvent.Probed>()
        .firstOrNull { it.host == h.host && it.result.kind == OutcomeKind.ACCEPTED }
        ?.result?.evidence

    private fun iso(ms: Long) = Instant.ofEpochMilli(ms).toString().let {
        if (it.length > 20 && it.endsWith("Z") && it.contains('.')) it.substringBefore('.') + "Z" else it
    }

    private val LINE_BREAKS = Regex("[\\r\\n]+")

    private fun text(s: String) = s.replace(LINE_BREAKS, " ")

    private fun cell(s: String) = text(s).replace("|", "\\|")
}
