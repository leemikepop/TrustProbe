package io.github.leemikepop.trustprobe.core.report

import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.ForwardReason
import io.github.leemikepop.trustprobe.core.probe.HostVerdict
import io.github.leemikepop.trustprobe.core.probe.InconclusiveReason
import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import io.github.leemikepop.trustprobe.core.probe.Verdict
import io.github.leemikepop.trustprobe.core.probe.VerdictEngine
import kotlinx.serialization.Serializable

@Serializable
data class Report(
    val packageName: String,
    val appLabel: String,
    val startedAt: Long,
    val endedAt: Long,
    val appVerdict: Verdict,
    val appReason: InconclusiveReason?,
    val hosts: List<HostVerdict>,
    val events: List<EngineEvent>,
)

object ReportBuilder {
    private val VERDICT_ORDER = listOf(Verdict.VULNERABLE, Verdict.INCONCLUSIVE, Verdict.PASS)

    fun build(
        packageName: String,
        appLabel: String,
        startedAt: Long,
        endedAt: Long,
        events: List<EngineEvent>,
    ): Report {
        val ordered = events.sortedBy { it.atMillis }.map(::capDetail) // stable
        val results = LinkedHashMap<String, MutableList<ProbeResult>>()
        val noSni = HashSet<String>()
        for (e in ordered) {
            when (e) {
                is EngineEvent.Probed -> results.getOrPut(e.host) { mutableListOf() } += e.result
                is EngineEvent.Forwarded -> if (e.reason == ForwardReason.NO_SNI) noSni += e.host
                is EngineEvent.QuicDropped -> Unit
            }
        }
        val hosts = (results.keys + noSni).distinct()
            .map { VerdictEngine.host(it, results[it].orEmpty(), it in noSni) }
            .sortedWith(compareBy({ VERDICT_ORDER.indexOf(it.verdict) }, { it.host }))
        val (verdict, reason) = VerdictEngine.app(hosts)
        return Report(packageName, appLabel, startedAt, endedAt, verdict, reason, hosts, ordered)
    }

    private const val MAX_DETAIL = 200

    /** `detail` is exception text kept for the JSON export only: bound it and strip control chars. */
    private fun capDetail(e: EngineEvent): EngineEvent {
        if (e !is EngineEvent.Probed) return e
        val d = e.result.detail ?: return e
        val clean = d.take(MAX_DETAIL).map { if (it < ' ' || it == '\u007F') ' ' else it }.joinToString("")
        return e.copy(result = e.result.copy(detail = clean))
    }
}
