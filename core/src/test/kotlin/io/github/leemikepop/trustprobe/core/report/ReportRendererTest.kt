package io.github.leemikepop.trustprobe.core.report

import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.ForwardReason
import io.github.leemikepop.trustprobe.core.evidence.RequestEvidence
import io.github.leemikepop.trustprobe.core.evidence.RequestEvidenceParser
import io.github.leemikepop.trustprobe.core.probe.InconclusiveReason
import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import io.github.leemikepop.trustprobe.core.probe.RejectStage
import io.github.leemikepop.trustprobe.core.probe.Severity
import io.github.leemikepop.trustprobe.core.probe.Verdict
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportRendererTest {
    private fun result(case: ProbeCase, kind: OutcomeKind, evidence: RequestEvidence? = null) = ProbeResult(
        case, kind,
        if (kind == OutcomeKind.REJECTED) RejectStage.ALERT_OR_CLOSE_DURING_HANDSHAKE else null,
        null, "TLSv1.3", evidence, 120,
    )

    private fun probed(host: String, at: Long, case: ProbeCase, kind: OutcomeKind, ev: RequestEvidence? = null) =
        EngineEvent.Probed(host, at, result(case, kind, ev))

    private fun build(events: List<EngineEvent>, label: String = "Demo") =
        ReportBuilder.build("com.example", label, 1_700_000_000_000, 1_700_000_042_000, events)

    @Test
    fun buildsHostVerdictsFromEvents() {
        val report = build(
            listOf(
                EngineEvent.Forwarded("10.0.0.1", 1, ForwardReason.NO_SNI),
                probed("api.example.com", 2, ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.REJECTED),
                EngineEvent.Forwarded("plain.example.com", 3, ForwardReason.NOT_TLS),
                EngineEvent.QuicDropped("quic.example.com", 4),
            ),
        )
        assertEquals(listOf("api.example.com", "10.0.0.1"), report.hosts.map { it.host }.sortedBy { it != "api.example.com" })
        val noSni = report.hosts.single { it.host == "10.0.0.1" }
        assertEquals(Verdict.INCONCLUSIVE, noSni.verdict)
        assertEquals(InconclusiveReason.NO_SNI, noSni.reason)
        assertEquals(Verdict.PASS, report.hosts.single { it.host == "api.example.com" }.verdict)
        assertEquals(2, report.hosts.size)
        assertEquals(Verdict.PASS, report.appVerdict)
        assertTrue(ReportRenderer.markdown(report).contains("Not tested: 1 non-TLS connections, 1 QUIC flows dropped"))
    }

    @Test
    fun hostsOrderedByVerdict() {
        val report = build(
            listOf(
                probed("z-pass.com", 1, ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.REJECTED),
                probed("a-pass.com", 2, ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.REJECTED),
                probed("m-inc.com", 3, ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.TIMEOUT),
                probed("z-vuln.com", 4, ProbeCase.T3_WRONG_HOST, OutcomeKind.ACCEPTED),
                probed("b-vuln.com", 5, ProbeCase.T1_SELF_SIGNED, OutcomeKind.ACCEPTED),
            ),
        )
        assertEquals(listOf("b-vuln.com", "z-vuln.com", "m-inc.com", "a-pass.com", "z-pass.com"), report.hosts.map { it.host })
        assertEquals(Verdict.VULNERABLE, report.appVerdict)
    }

    @Test
    fun markdownContainsTableAndEvidence() {
        val ev = RequestEvidenceParser.parse("GET /v1/me?x=1 HTTP/1.1\r\nHost: bad.example.com\r\nX-Token: abcdefgh12345\r\n\r\n".toByteArray())
        val md = ReportRenderer.markdown(build(listOf(probed("bad.example.com", 1, ProbeCase.T3_WRONG_HOST, OutcomeKind.ACCEPTED, ev))))
        assertTrue(md.startsWith("# TrustProbe report: Demo"))
        assertTrue(md.contains("| Host | Verdict | Severity / reason | Cases run | Notes |"))
        assertTrue(md.contains("| bad.example.com | VULNERABLE | ${Severity.ACCEPTS_ANY_CERT.name} | T3_WRONG_HOST |"))
        assertTrue(md.contains("2023-11-14T22:13:20Z"))
        assertTrue(md.contains("(42s)"))
        assertTrue(md.contains("## Evidence"))
        assertTrue(md.contains("- Method: GET"))
        assertTrue(md.contains("- Host: bad.example.com"))
        assertTrue(md.contains("X-Token: abcd"))
        assertFalse(md.contains("abcdefgh12345"))
    }

    @Test
    fun jsonRoundTrips() {
        val ev = RequestEvidenceParser.parse("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n".toByteArray())
        val report = build(
            listOf(
                probed("a.com", 1, ProbeCase.T1_SELF_SIGNED, OutcomeKind.ACCEPTED, ev),
                EngineEvent.Forwarded("b.com", 2, ForwardReason.HOST_DONE),
                EngineEvent.QuicDropped("c.com", 3),
            ),
        )
        val text = ReportRenderer.json(report)
        assertEquals(report, Json.decodeFromString(Report.serializer(), text))
    }

    @Test
    fun exportsNeverContainRawHeaderValue() {
        val secret = "s3cr3t-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"
        val ev = RequestEvidenceParser.parse(
            "POST /login?token=$secret HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $secret\r\n\r\n".toByteArray(),
        )
        val report = build(listOf(probed("api.example.com", 1, ProbeCase.T3_WRONG_HOST, OutcomeKind.ACCEPTED, ev)))
        val md = ReportRenderer.markdown(report)
        val json = ReportRenderer.json(report)
        assertTrue(md.contains("Authorization"))
        assertFalse(md.contains(secret))
        assertFalse(json.contains(secret))
        assertFalse(md.contains("ABCDEFGHIJ"))
        assertFalse(json.contains("ABCDEFGHIJ"))
    }

    @Test
    fun markdownEscapesTableCells() {
        val md = ReportRenderer.markdown(build(listOf(probed("evil|host\nname.com", 1, ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.REJECTED)), "Ap|p\nX"))
        assertTrue(md.contains("| evil\\|host name.com | PASS |"))
        assertTrue(md.lines().first() == "# TrustProbe report: Ap|p X")
        val row = md.lines().single { it.startsWith("| evil") }
        assertEquals(6, row.replace("\\|", "").count { it == '|' })
    }
}
