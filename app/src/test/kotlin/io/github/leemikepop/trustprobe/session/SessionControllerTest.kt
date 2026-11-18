package io.github.leemikepop.trustprobe.session

import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.ForwardReason
import io.github.leemikepop.trustprobe.core.ProbeEngine
import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import io.github.leemikepop.trustprobe.core.probe.Verdict
import io.github.leemikepop.trustprobe.core.report.ReportRenderer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionControllerTest {
    private val scope = CoroutineScope(SupervisorJob())
    private var now = 1_000L
    private lateinit var sendEvent: (EngineEvent) -> Unit
    private lateinit var sendPlaintext: (String, ProbeCase, ByteArray) -> Unit
    private val store = RecordingStore()

    /** Hands the controller a real (idle) engine and keeps its callbacks so tests can drive them. */
    private val controller = SessionController(
        engineFactory = { onEvent, onPlaintext ->
            sendEvent = onEvent
            sendPlaintext = onPlaintext
            ProbeEngine(scope, onEvent = {})
        },
        clock = { now },
        store = store,
    )

    @After
    fun tearDown() {
        scope.cancel()
    }

    private fun probed(host: String, case: ProbeCase, kind: OutcomeKind, at: Long) =
        EngineEvent.Probed(host, at, ProbeResult(case, kind, null, null, "TLSv1.3", null, 5))

    @Test
    fun beginThenEndBuildsReport() {
        val port = controller.begin("com.example.app", "Example", durationSec = 120)
        assertTrue(port in 1..65535)
        assertEquals(SessionState.Running("com.example.app", 1_000L + 120_000L), controller.state.value)
        assertNotNull(controller.credentials)
        assertEquals(port, controller.socksPort)

        val accepted = probed("a.example", ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.ACCEPTED, 1_100)
        val forwarded = EngineEvent.Forwarded("b.example:80", 1_200, ForwardReason.NON_TLS_PORT)
        sendEvent(accepted)
        sendEvent(forwarded)
        assertEquals(listOf(accepted, forwarded), controller.liveEvents.value)

        now = 5_000L
        val report = controller.end()

        assertEquals("com.example.app", report.packageName)
        assertEquals("Example", report.appLabel)
        assertEquals(1_000L, report.startedAt)
        assertEquals(5_000L, report.endedAt)
        assertEquals(listOf(accepted, forwarded), report.events)
        assertEquals(Verdict.VULNERABLE, report.appVerdict)
        assertEquals(SessionState.Finished(report), controller.state.value)
        assertNull(controller.credentials)
        assertNull(controller.socksPort)

        val session = store.sessions.single()
        assertEquals(listOf<EngineEvent>(accepted, forwarded), session.events)
        assertEquals(5_000L, session.endedAt)
        assertEquals(120, session.durationLimitSec)
    }

    @Test
    fun endIsIdempotent() {
        controller.begin("com.example.app", "Example")
        sendEvent(probed("a.example", ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.REJECTED, 1_100))
        val first = controller.end()
        now = 9_000L
        val second = controller.end()
        assertSame(first, second)
        assertEquals(1, store.sessions.single().finishCalls)
    }

    @Test
    fun onRevokeEndsSessionWithReport() {
        // TunnelService.onRevoke() stops hev, closes the tun fd, then calls end(): the controller
        // side of that path is just end() while Running.
        controller.begin("com.example.app", "Example")
        val e = probed("a.example", ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.ACCEPTED, 1_100)
        sendEvent(e)
        assertTrue(controller.state.value is SessionState.Running)

        controller.end()

        val state = controller.state.value
        assertTrue(state is SessionState.Finished)
        assertEquals(listOf<EngineEvent>(e), (state as SessionState.Finished).report.events)
    }

    @Test
    fun plaintextIsNotInReport() {
        controller.begin("com.example.app", "Example")
        val secret = "GET /login?token=SUPERSECRET123 HTTP/1.1\r\nHost: a.example\r\n\r\n".toByteArray()
        sendPlaintext("a.example", ProbeCase.T2_UNTRUSTED_CA, secret)
        sendEvent(probed("a.example", ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.ACCEPTED, 1_100))

        assertTrue(controller.plaintext["a.example/T2_UNTRUSTED_CA"].contentEquals(secret))

        val report = controller.end()
        assertFalse(ReportRenderer.json(report).contains("SUPERSECRET123"))
        assertFalse(ReportRenderer.markdown(report).contains("SUPERSECRET123"))
        assertFalse(store.sessions.single().events.toString().contains("SUPERSECRET123"))
    }

    @Test
    fun discardFinishedDeletesAnEmptySessionOnce() {
        controller.begin("com.example.app", "Example")
        controller.end()

        controller.discardFinished()
        controller.discardFinished()

        assertEquals(listOf(1L), store.discarded)
    }

    @Test
    fun discardFinishedKeepsASessionWithEvents() {
        controller.begin("com.example.app", "Example")
        sendEvent(probed("a.example", ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.REJECTED, 1_100))
        controller.end()

        controller.discardFinished()

        assertEquals(emptyList<Long>(), store.discarded)
    }

    @Test
    fun engineFailureAtBeginLeavesNoStoredSession() {
        val failing = SessionController({ _, _ -> error("no engine") }, { now }, store)

        assertTrue(runCatching { failing.begin("com.example.app", "Example") }.isFailure)

        assertEquals(listOf(1L), store.discarded)
        assertEquals(SessionState.Idle, failing.state.value)
        assertNull(failing.credentials)
    }

    @Test
    fun clearPlaintextDropsUnredactedBytes() {
        controller.begin("com.example.app", "Example")
        sendPlaintext("a.example", ProbeCase.T2_UNTRUSTED_CA, "GET / HTTP/1.1\r\n\r\n".toByteArray())
        controller.end()
        assertEquals(1, controller.plaintext.size)

        controller.clearPlaintext()

        assertTrue(controller.plaintext.isEmpty())
    }

    @Test
    fun eventsAfterEndAreIgnored() {
        controller.begin("com.example.app", "Example")
        val before = probed("a.example", ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.ACCEPTED, 1_100)
        sendEvent(before)
        val report = controller.end()

        // An in-flight engine callback may still land after stop().
        sendEvent(probed("late.example", ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.ACCEPTED, 1_300))
        sendPlaintext("late.example", ProbeCase.T2_UNTRUSTED_CA, "GET / HTTP/1.1\r\n\r\n".toByteArray())

        assertEquals(listOf<EngineEvent>(before), controller.liveEvents.value)
        assertNull(controller.plaintext["late.example/T2_UNTRUSTED_CA"])
        assertEquals(listOf<EngineEvent>(before), store.sessions.single().events)
        assertSame(report, (controller.state.value as SessionState.Finished).report)
    }
}

/** Records what the controller writes, like the Room store will persist it. */
private class RecordingStore : SessionStore {
    class Record(val durationLimitSec: Int) {
        val events = mutableListOf<EngineEvent>()
        var endedAt: Long? = null
        var finishCalls = 0
    }

    val sessions = mutableListOf<Record>()
    val discarded = mutableListOf<Long>()

    @Synchronized
    override fun open(packageName: String, appLabel: String, startedAt: Long, durationLimitSec: Int): Long {
        sessions += Record(durationLimitSec)
        return sessions.size.toLong()
    }

    @Synchronized
    override fun append(sessionId: Long, e: EngineEvent) {
        sessions[sessionId.toInt() - 1].events += e
    }

    @Synchronized
    override fun finish(sessionId: Long, endedAt: Long) {
        sessions[sessionId.toInt() - 1].apply { this.endedAt = endedAt; finishCalls++ }
    }

    @Synchronized
    override fun discard(sessionId: Long) {
        discarded += sessionId
    }
}
