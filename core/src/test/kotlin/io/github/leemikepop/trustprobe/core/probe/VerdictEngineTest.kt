package io.github.leemikepop.trustprobe.core.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VerdictEngineTest {
    private fun r(case: ProbeCase, kind: OutcomeKind) =
        ProbeResult(case, kind, null, null, null, null, 0)

    private val t1 = ProbeCase.T1_SELF_SIGNED
    private val t2 = ProbeCase.T2_UNTRUSTED_CA
    private val t3 = ProbeCase.T3_WRONG_HOST
    private val acc = OutcomeKind.ACCEPTED
    private val rej = OutcomeKind.REJECTED

    @Test
    fun t2AndT3AcceptedIsAnyCert() {
        val v = VerdictEngine.host("h", listOf(r(t2, acc), r(t3, acc)))
        assertEquals(Verdict.VULNERABLE, v.verdict)
        assertEquals(Severity.ACCEPTS_ANY_CERT, v.severity)
        assertFalse(v.hostnameUntested)
        assertEquals(listOf(t2, t3), v.casesRun)
    }

    @Test
    fun t2AcceptedOnlyIsNoChainAndHostnameUntested() {
        val v = VerdictEngine.host("h", listOf(r(t2, acc)))
        assertEquals(Severity.NO_CHAIN_VALIDATION, v.severity)
        assertTrue(v.hostnameUntested)
    }

    @Test
    fun t3RejectedAfterT2AcceptedKeepsNoChainWithHostnameTested() {
        val v = VerdictEngine.host("h", listOf(r(t2, acc), r(t3, rej)))
        assertEquals(Severity.NO_CHAIN_VALIDATION, v.severity)
        assertFalse(v.hostnameUntested)
    }

    @Test
    fun t2RejectedT1AcceptedIsSelfSigned() {
        val v = VerdictEngine.host("h", listOf(r(t2, rej), r(t1, acc)))
        assertEquals(Verdict.VULNERABLE, v.verdict)
        assertEquals(Severity.ACCEPTS_SELF_SIGNED, v.severity)
        assertFalse(v.hostnameUntested)
    }

    @Test
    fun lateT2AcceptedAfterRejectedStillVulnerable() {
        val v = VerdictEngine.host("h", listOf(r(t2, rej), r(t2, acc)))
        assertEquals(Verdict.VULNERABLE, v.verdict)
        assertEquals(Severity.NO_CHAIN_VALIDATION, v.severity)
        assertTrue(v.hostnameUntested)
        assertEquals(listOf(t2), v.casesRun)
    }

    @Test
    fun t2RejectedOnlyIsPassWithSelfSignedUntested() {
        val v = VerdictEngine.host("h", listOf(r(t2, rej)))
        assertEquals(Verdict.PASS, v.verdict)
        assertNull(v.severity)
        assertTrue(v.selfSignedUntested)
        assertFalse(v.hostnameUntested)
    }

    @Test
    fun t2AndT1RejectedIsPassFullyTested() {
        val v = VerdictEngine.host("h", listOf(r(t2, rej), r(t1, rej)))
        assertEquals(Verdict.PASS, v.verdict)
        assertFalse(v.selfSignedUntested)
        assertEquals(listOf(t2, t1), v.casesRun)
    }

    @Test
    fun casesRunExcludesTimeouts() {
        val v = VerdictEngine.host("h", listOf(r(t2, OutcomeKind.TIMEOUT), r(t2, rej)))
        assertEquals(listOf(t2), v.casesRun)
    }

    @Test
    fun inconclusiveReasonPrecedence() {
        val to = r(t2, OutcomeKind.TIMEOUT)
        val er = r(t2, OutcomeKind.ERROR)
        assertEquals(InconclusiveReason.NO_SNI, VerdictEngine.host("h", listOf(to, er), sawNoSni = true).reason)
        assertEquals(InconclusiveReason.TIMEOUT, VerdictEngine.host("h", listOf(er, to)).reason)
        assertEquals(InconclusiveReason.ERROR, VerdictEngine.host("h", listOf(er)).reason)
        val none = VerdictEngine.host("h", emptyList())
        assertEquals(Verdict.INCONCLUSIVE, none.verdict)
        assertEquals(InconclusiveReason.NO_CONNECTIONS, none.reason)
        assertFalse(none.selfSignedUntested)
    }

    private fun hv(v: Verdict, reason: InconclusiveReason? = null) =
        HostVerdict("h", v, null, reason, emptyList(), false, false)

    @Test
    fun appLevel() {
        assertEquals(Verdict.INCONCLUSIVE to InconclusiveReason.NO_CONNECTIONS, VerdictEngine.app(emptyList()))
        assertEquals(
            Verdict.VULNERABLE to null,
            VerdictEngine.app(listOf(hv(Verdict.PASS), hv(Verdict.VULNERABLE))),
        )
        assertEquals(
            Verdict.PASS to null,
            VerdictEngine.app(listOf(hv(Verdict.INCONCLUSIVE, InconclusiveReason.TIMEOUT), hv(Verdict.PASS))),
        )
        assertEquals(
            Verdict.INCONCLUSIVE to InconclusiveReason.TIMEOUT,
            VerdictEngine.app(
                listOf(
                    hv(Verdict.INCONCLUSIVE, InconclusiveReason.ERROR),
                    hv(Verdict.INCONCLUSIVE, InconclusiveReason.TIMEOUT),
                ),
            ),
        )
    }
}
