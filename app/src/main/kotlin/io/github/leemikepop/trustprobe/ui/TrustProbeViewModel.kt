package io.github.leemikepop.trustprobe.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.report.Report
import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import io.github.leemikepop.trustprobe.data.SessionEntity
import io.github.leemikepop.trustprobe.session.SessionState
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AppInfo(val packageName: String, val label: String)

/** Launchable apps installed on the device (including TrustProbe itself; the ViewModel drops it). */
interface AppCatalog {
    suspend fun launchableApps(): List<AppInfo>
}

/** The slice of `SessionController` the UI uses, so the ViewModel can be tested without an engine. */
interface SessionGateway {
    val state: StateFlow<SessionState>
    val liveEvents: StateFlow<List<EngineEvent>>
    val credentials: Socks5Credentials?

    /** Unredacted first-request bytes keyed `"$host/$case"`; memory only, never exported. */
    val plaintext: Map<String, ByteArray>

    /** Blocks on a database insert: call off the main thread. */
    fun begin(packageName: String, appLabel: String, durationSec: Int): Int
    fun end(): Report

    /** Deletes the just-finished session from history if it recorded nothing. */
    fun discardFinished()

    /** Drops the unredacted first requests from memory. */
    fun clearPlaintext()
}

/** Past sessions; reports are rebuilt lazily, one at a time. */
interface HistorySource {
    fun sessions(): Flow<List<SessionEntity>>
    suspend fun report(id: Long): Report?
}

interface TunnelLauncher {
    fun start(packageName: String, socksPort: Int, credentials: Socks5Credentials, durationSec: Int)
    fun stop()
}

/** Navigation is a plain state: four screens do not need a nav library. */
sealed interface Screen {
    data object Picker : Screen
    data object Session : Screen
    data object Report : Screen
    data object History : Screen
}

/**
 * [canReveal] is true only for the session that just finished in this process, until its content is
 * hidden again; a report reopened from history has no plaintext to show.
 */
data class ReportUi(val report: Report, val canReveal: Boolean, val revealed: Boolean = false)

class TrustProbeViewModel(
    private val catalog: AppCatalog,
    private val session: SessionGateway,
    private val history: HistorySource,
    private val tunnel: TunnelLauncher,
    private val selfPackage: String,
    private val io: CoroutineDispatcher = Dispatchers.IO,
    private val savedState: SavedStateHandle = SavedStateHandle(),
) : ViewModel() {
    private val allApps = MutableStateFlow<List<AppInfo>>(emptyList())
    private val _query = MutableStateFlow("")
    private val _durationMin = MutableStateFlow(DEFAULT_MINUTES)
    private val _screen = MutableStateFlow<Screen>(Screen.Picker)
    private val _reportUi = MutableStateFlow<ReportUi?>(null)
    private val _error = MutableStateFlow<String?>(null)
    private val _starting = MutableStateFlow(false)
    private val _selected = MutableStateFlow(
        savedState.get<String>(KEY_SEL_PKG)?.let { AppInfo(it, savedState.get<String>(KEY_SEL_LABEL) ?: it) },
    )
    private var reportFromHistory = false
    private var startAborted = false
    private var stopRequested = false

    val query: StateFlow<String> = _query.asStateFlow()
    val durationMin: StateFlow<Int> = _durationMin.asStateFlow()
    val screen: StateFlow<Screen> = _screen.asStateFlow()
    val reportUi: StateFlow<ReportUi?> = _reportUi.asStateFlow()
    val error: StateFlow<String?> = _error.asStateFlow()
    val starting: StateFlow<Boolean> = _starting.asStateFlow()

    /** The app chosen in the picker; it survives the VPN consent and permission round trips. */
    val selected: StateFlow<AppInfo?> = _selected.asStateFlow()
    val sessionState: StateFlow<SessionState> get() = session.state
    val liveEvents: StateFlow<List<EngineEvent>> get() = session.liveEvents

    val apps: StateFlow<List<AppInfo>> = combine(allApps, _query) { all, q ->
        val needle = q.trim()
        all.filter { it.packageName != selfPackage }
            .filter { needle.isEmpty() || it.label.contains(needle, true) || it.packageName.contains(needle, true) }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    /** Past sessions, newest first; null until the first load. */
    val sessions: StateFlow<List<SessionEntity>?> =
        history.sessions().stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    /** The label of the app under test, falling back to its package name. */
    fun labelFor(packageName: String): String =
        if (savedState.get<String>(KEY_RUN_PKG) == packageName) {
            savedState.get<String>(KEY_RUN_LABEL) ?: packageName
        } else {
            packageName
        }

    init {
        viewModelScope.launch { allApps.value = withContext(io) { catalog.launchableApps() } }
        viewModelScope.launch {
            var first = true
            session.state.collect { s ->
                when (s) {
                    SessionState.Idle -> Unit
                    is SessionState.Running -> {
                        _reportUi.value = null
                        _screen.value = Screen.Session
                    }
                    is SessionState.Finished -> {
                        when {
                            first -> Unit // a finished session left over from before this screen existed
                            startAborted -> {
                                startAborted = false
                                session.discardFinished()
                                _screen.value = Screen.Picker
                            }
                            !stopRequested && s.report.events.isEmpty() &&
                                s.report.endedAt - s.report.startedAt < START_FAILURE_WINDOW_MS -> {
                                // The service refused the start and ended the session: nothing to report.
                                session.discardFinished()
                                _error.value = "Test could not start."
                                _screen.value = Screen.Picker
                            }
                            else -> showReport(ReportUi(s.report, canReveal = true), fromHistory = false)
                        }
                        stopRequested = false
                    }
                }
                first = false
            }
        }
    }

    fun setQuery(q: String) {
        _query.value = q
    }

    fun select(app: AppInfo) {
        _selected.value = app
        savedState[KEY_SEL_PKG] = app.packageName
        savedState[KEY_SEL_LABEL] = app.label
    }

    fun setDuration(minutes: Int) {
        require(minutes in DURATIONS_MIN)
        _durationMin.value = minutes
    }

    fun onConsentDenied() {
        _error.value = "VPN permission is needed to run a test."
    }

    fun dismissError() {
        _error.value = null
    }

    /** Call once VPN consent is granted. Opens the session off the main thread, then starts the tunnel. */
    fun start(app: AppInfo) {
        if (_starting.value || session.state.value is SessionState.Running) return
        _starting.value = true
        _error.value = null
        stopRequested = false
        val durationSec = _durationMin.value * 60
        savedState[KEY_RUN_PKG] = app.packageName
        savedState[KEY_RUN_LABEL] = app.label
        viewModelScope.launch {
            try {
                val port = withContext(io) { session.begin(app.packageName, app.label, durationSec) }
                try {
                    tunnel.start(app.packageName, port, checkNotNull(session.credentials), durationSec)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    // Set before end(): the state collector may see Finished as soon as end() returns.
                    startAborted = true
                    val ended = runCatching { session.end() }
                    if (ended.isFailure) {
                        startAborted = false
                        throw IllegalStateException(
                            "${e.message ?: e.javaClass.simpleName} (the session could not be closed: " +
                                "${ended.exceptionOrNull()?.message}; press Stop)",
                            e,
                        )
                    }
                    throw e
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _error.value = "Could not start the test: ${e.message ?: e.javaClass.simpleName}"
            } finally {
                _starting.value = false
            }
        }
    }

    /**
     * Asks the service to stop. If no service owns the session (it never started, or died), the
     * controller would stay Running forever, so end it here when nothing ended it shortly after.
     */
    fun stop() {
        stopRequested = true // a quick stop is the user's choice, not a failed start
        tunnel.stop()
        viewModelScope.launch {
            delay(ORPHAN_GRACE_MS)
            if (session.state.value is SessionState.Running) withContext(io) { runCatching { session.end() } }
        }
    }

    fun openHistory() {
        _screen.value = Screen.History
    }

    fun openHistory(sessionId: Long) {
        viewModelScope.launch {
            val report = try {
                withContext(io) { history.report(sessionId) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _error.value = "This report could not be loaded."
                return@launch
            }
            if (report == null) {
                _error.value = "This report no longer exists."
            } else {
                showReport(ReportUi(report, canReveal = false), fromHistory = true)
            }
        }
    }

    /** Leaving the report of the session that just finished also drops its unredacted content. */
    fun back() {
        if (_screen.value == Screen.Report && _reportUi.value?.canReveal == true) session.clearPlaintext()
        _reportUi.value = _reportUi.value?.copy(revealed = false)
        _screen.value = when (_screen.value) {
            Screen.Report -> if (reportFromHistory) Screen.History else Screen.Picker
            else -> Screen.Picker
        }
    }

    /** Hiding the full content also drops it from memory, so it cannot be shown again. */
    fun toggleReveal() {
        val ui = _reportUi.value ?: return
        if (!ui.canReveal) return
        if (ui.revealed) {
            session.clearPlaintext()
            _reportUi.value = ui.copy(revealed = false, canReveal = false)
        } else {
            _reportUi.value = ui.copy(revealed = true)
        }
    }

    /** The unmasked first request for an accepted case, or null unless the user asked to reveal it. */
    fun fullContent(host: String, case: ProbeCase): String? {
        val ui = _reportUi.value ?: return null
        if (!ui.canReveal || !ui.revealed) return null
        return session.plaintext["$host/$case"]?.let { String(it, Charsets.UTF_8) }
    }

    private fun showReport(ui: ReportUi, fromHistory: Boolean) {
        reportFromHistory = fromHistory
        _reportUi.value = ui
        _screen.value = Screen.Report
    }

    companion object {
        private const val KEY_SEL_PKG = "selectedPackage"
        private const val KEY_SEL_LABEL = "selectedLabel"
        private const val KEY_RUN_PKG = "runningPackage"
        private const val KEY_RUN_LABEL = "runningLabel"
        private const val START_FAILURE_WINDOW_MS = 5_000L
        private const val ORPHAN_GRACE_MS = 2_000L
        const val DEFAULT_MINUTES = 5
        val DURATIONS_MIN = listOf(2, 5, 10)
    }
}

private val FILE_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmm")

/** `trustprobe-<package>-<yyyyMMdd-HHmm>.<ext>`, with the time of the session start. */
fun exportFileName(report: Report, ext: String, zone: ZoneId = ZoneId.systemDefault()): String =
    "trustprobe-${report.packageName.replace(Regex("[^A-Za-z0-9._-]"), "_")}-${FILE_STAMP.format(Instant.ofEpochMilli(report.startedAt).atZone(zone))}.$ext"
