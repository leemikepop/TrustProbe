package io.github.leemikepop.trustprobe.session

import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.ProbeEngine
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.report.Report
import io.github.leemikepop.trustprobe.core.report.ReportBuilder
import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

sealed interface SessionState {
    data object Idle : SessionState
    data class Running(val packageName: String, val endsAt: Long) : SessionState
    data class Finished(val report: Report) : SessionState
}

/**
 * Runs one test session at a time: starts a [ProbeEngine], collects its events, and builds the
 * report when the session ends. Engine callbacks arrive concurrently on worker threads; once
 * [end] has run, late callbacks from the stopped engine are ignored.
 */
class SessionController(
    private val engineFactory: (
        onEvent: (EngineEvent) -> Unit,
        onPlaintext: (String, ProbeCase, ByteArray) -> Unit,
    ) -> ProbeEngine,
    private val clock: () -> Long,
    private val store: SessionStore,
) {
    private class Active(
        val id: Long,
        val packageName: String,
        val appLabel: String,
        val startedAt: Long,
    ) {
        lateinit var engine: ProbeEngine
        var port = 0
        val events = ArrayList<EngineEvent>() // guarded by this
        var ended = false // guarded by this
    }

    private val lock = Any()
    private val _state = MutableStateFlow<SessionState>(SessionState.Idle)
    private val _liveEvents = MutableStateFlow<List<EngineEvent>>(emptyList())
    private val _plaintext = ConcurrentHashMap<String, ByteArray>()
    @Volatile private var active: Active? = null

    val state: StateFlow<SessionState> = _state.asStateFlow()
    val liveEvents: StateFlow<List<EngineEvent>> = _liveEvents.asStateFlow()

    /** First decrypted request bytes, UNREDACTED, keyed `"$host/$case"`. Memory only. */
    val plaintext: Map<String, ByteArray> get() = _plaintext

    /** Credentials the tunnel must present to the running engine; null when no session runs. */
    val credentials: Socks5Credentials? get() = active?.engine?.credentials

    /** The running engine's SOCKS5 port on 127.0.0.1; null when no session runs. */
    val socksPort: Int? get() = active?.port

    /** Starts the engine for [packageName] and returns its SOCKS5 port on 127.0.0.1. */
    fun begin(packageName: String, appLabel: String, durationSec: Int = 300): Int = synchronized(lock) {
        check(active == null) { "a session is already running" }
        require(durationSec > 0) { "durationSec must be positive" }
        val startedAt = clock()
        val id = store.open(packageName, appLabel, startedAt, durationSec)
        val session = Active(id, packageName, appLabel, startedAt)
        _liveEvents.value = emptyList()
        _plaintext.clear()
        session.engine = engineFactory(
            { e -> onEvent(session, e) },
            { host, case, bytes -> onPlaintext(session, host, case, bytes) },
        )
        val port = try {
            session.engine.start()
        } catch (e: Exception) {
            session.engine.stop()
            store.finish(id, clock())
            throw e
        }
        session.port = port
        active = session
        _state.value = SessionState.Running(packageName, startedAt + durationSec * 1_000L)
        port
    }

    /** Stops the engine and builds the report. Calling it again returns the same report. */
    fun end(): Report = synchronized(lock) {
        (_state.value as? SessionState.Finished)?.let { return it.report }
        val session = checkNotNull(active) { "no session has begun" }
        val events = synchronized(session) {
            session.ended = true
            session.events.toList()
        }
        session.engine.stop()
        val endedAt = clock()
        store.finish(session.id, endedAt)
        val report = ReportBuilder.build(session.packageName, session.appLabel, session.startedAt, endedAt, events)
        active = null
        _state.value = SessionState.Finished(report)
        report
    }

    private fun onEvent(session: Active, e: EngineEvent): Unit = synchronized(session) {
        if (session.ended) return
        session.events += e
        store.append(session.id, e)
        _liveEvents.update { it + e }
    }

    private fun onPlaintext(session: Active, host: String, case: ProbeCase, bytes: ByteArray): Unit =
        synchronized(session) {
            if (session.ended) return
            _plaintext["$host/$case"] = bytes
        }
}
