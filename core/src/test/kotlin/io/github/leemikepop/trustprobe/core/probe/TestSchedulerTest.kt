package io.github.leemikepop.trustprobe.core.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TestSchedulerTest {
    private fun r(case: ProbeCase, kind: OutcomeKind) =
        ProbeResult(case, kind, null, null, null, null, 0)

    private val t1 = ProbeCase.T1_SELF_SIGNED
    private val t2 = ProbeCase.T2_UNTRUSTED_CA
    private val t3 = ProbeCase.T3_WRONG_HOST

    @Test
    fun rejectedT2ThenT1ThenForward() {
        val s = TestScheduler()
        assertEquals(t2, s.assign("a.com"))
        s.report("a.com", r(t2, OutcomeKind.REJECTED))
        assertEquals(t1, s.assign("a.com"))
        s.report("a.com", r(t1, OutcomeKind.REJECTED))
        assertNull(s.assign("a.com"))
    }

    @Test
    fun acceptedT2ThenT3() {
        val s = TestScheduler()
        assertEquals(t2, s.assign("a.com"))
        s.report("a.com", r(t2, OutcomeKind.ACCEPTED))
        assertEquals(t3, s.assign("a.com"))
        s.report("a.com", r(t3, OutcomeKind.ACCEPTED))
        assertNull(s.assign("a.com"))
    }

    @Test
    fun timeoutRetriesSameCaseOnceThenGivesUp() {
        val s = TestScheduler()
        assertEquals(t2, s.assign("a.com"))
        s.report("a.com", r(t2, OutcomeKind.TIMEOUT))
        assertEquals(t2, s.assign("a.com"))
        s.report("a.com", r(t2, OutcomeKind.ERROR))
        assertNull(s.assign("a.com"))
    }

    @Test
    fun parallelConnectionsShareInFlightCase() {
        val s = TestScheduler()
        assertEquals(t2, s.assign("a.com"))
        assertEquals(t2, s.assign("a.com"))
        s.report("a.com", r(t2, OutcomeKind.REJECTED))
        s.report("a.com", r(t2, OutcomeKind.REJECTED))
        assertEquals(t1, s.assign("a.com"))
    }

    @Test
    fun lateResultForOldCaseDoesNotAdvance() {
        val s = TestScheduler()
        s.assign("a.com")
        s.report("a.com", r(t2, OutcomeKind.REJECTED))
        s.report("a.com", r(t2, OutcomeKind.TIMEOUT))
        assertEquals(t1, s.assign("a.com"))
    }

    @Test
    fun unknownHostReportIgnored() {
        val s = TestScheduler()
        s.report("x.com", r(t2, OutcomeKind.REJECTED))
        assertEquals(t2, s.assign("x.com"))
    }

    @Test
    fun hostIsCaseInsensitive() {
        val s = TestScheduler()
        assertEquals(t2, s.assign("A.Com"))
        s.report("a.COM", r(t2, OutcomeKind.REJECTED))
        assertEquals(t1, s.assign("a.com"))
    }
}
