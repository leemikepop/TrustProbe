package io.github.leemikepop.trustprobe.ui

import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import io.github.leemikepop.trustprobe.core.probe.Verdict
import io.github.leemikepop.trustprobe.core.report.Report
import io.github.leemikepop.trustprobe.core.report.ReportBuilder
import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import io.github.leemikepop.trustprobe.data.SessionEntity
import io.github.leemikepop.trustprobe.session.SessionState
import java.time.ZoneId
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class TrustProbeViewModelTest {
    private val dispatcher = UnconfinedTestDispatcher()

    private class FakeCatalog(val apps: List<AppInfo>) : AppCatalog {
        override suspend fun launchableApps() = apps
    }

    private class FakeSession : SessionGateway {
        override val state = MutableStateFlow<SessionState>(SessionState.Idle)
        override val liveEvents: StateFlow<List<EngineEvent>> = MutableStateFlow(emptyList())
        override var credentials: Socks5Credentials? = null
        override val plaintext = HashMap<String, ByteArray>()
        var begun: Triple<String, String, Int>? = null
        var ended = 0
        var endFails = false
        var beginCount = 0
        var discards = 0

        override fun begin(packageName: String, appLabel: String, durationSec: Int): Int {
            beginCount++
            begun = Triple(packageName, appLabel, durationSec)
            credentials = Socks5Credentials("u", "p")
            state.value = SessionState.Running(packageName, 1_000L + durationSec * 1_000L)
            return 4242
        }

        override fun end(): Report {
            ended++
            if (endFails) throw IllegalStateException("end failed")
            return report("com.example.app").also { state.value = SessionState.Finished(it) }
        }

        override fun discardFinished() {
            discards++
        }

        override fun clearPlaintext() = plaintext.clear()
    }

    private class FakeHistory(
        val rows: List<SessionEntity> = emptyList(),
        val reports: Map<Long, Report> = emptyMap(),
        val failWith: Exception? = null,
    ) : HistorySource {
        override fun sessions(): Flow<List<SessionEntity>> = flowOf(rows)
        override suspend fun report(id: Long): Report? {
            failWith?.let { throw it }
            return reports[id]
        }
    }

    private class FakeTunnel(var failWith: Exception? = null) : TunnelLauncher {
        var started: String? = null
        var stops = 0
        override fun start(packageName: String, socksPort: Int, credentials: Socks5Credentials, durationSec: Int) {
            failWith?.let { throw it }
            started = "$packageName:$socksPort:$durationSec"
        }

        override fun stop() {
            stops++
        }
    }

    private val session = FakeSession()
    private val tunnel = FakeTunnel()

    @Before
    fun setUp() = Dispatchers.setMain(dispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun vm(
        apps: List<AppInfo> = emptyList(),
        history: HistorySource = FakeHistory(),
    ) = TrustProbeViewModel(FakeCatalog(apps), session, history, tunnel, SELF, dispatcher)

    @Test
    fun pickerListsOnlyLaunchableAppsExceptSelf() {
        val vm = vm(
            listOf(AppInfo("com.zed", "Zed"), AppInfo(SELF, "TrustProbe"), AppInfo("com.alpha", "alpha")),
        )
        assertEquals(listOf("alpha", "Zed"), vm.apps.value.map { it.label })
        vm.setQuery("ZE")
        assertEquals(listOf("com.zed"), vm.apps.value.map { it.packageName })
    }

    @Test
    fun finishedStateShowsReport() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        assertEquals("com.example.app:4242:300", tunnel.started) // default 5 minutes
        assertEquals(Screen.Session, vm.screen.value)

        session.state.value = SessionState.Finished(report("com.example.app"))

        assertEquals(Screen.Report, vm.screen.value)
        val shown = vm.reportUi.value
        assertNotNull(shown)
        assertEquals(Verdict.VULNERABLE, shown!!.report.appVerdict)
        assertTrue(shown.canReveal)
    }

    @Test
    fun revealToggleOnlyAffectsCurrentSession() {
        val old = report("com.old")
        val vm = vm(history = FakeHistory(reports = mapOf(7L to old)))
        vm.start(AppInfo("com.example.app", "Example"))
        session.plaintext["a.example/T2_UNTRUSTED_CA"] = "GET / HTTP/1.1\r\nAuthorization: Bearer secret\r\n".toByteArray()
        session.state.value = SessionState.Finished(report("com.example.app"))

        assertNull(vm.fullContent("a.example", ProbeCase.T2_UNTRUSTED_CA)) // masked until asked
        vm.toggleReveal()
        assertTrue(vm.reportUi.value!!.revealed)
        assertEquals(
            "GET / HTTP/1.1\r\nAuthorization: Bearer secret\r\n",
            vm.fullContent("a.example", ProbeCase.T2_UNTRUSTED_CA),
        )

        vm.back()
        vm.openHistory(7L)
        assertEquals(Screen.Report, vm.screen.value)
        assertEquals("com.old", vm.reportUi.value!!.report.packageName)
        assertFalse(vm.reportUi.value!!.canReveal)
        vm.toggleReveal()
        assertFalse(vm.reportUi.value!!.revealed)
        assertNull(vm.fullContent("a.example", ProbeCase.T2_UNTRUSTED_CA))
        assertTrue(session.plaintext.isEmpty()) // leaving the live report dropped it
    }

    @Test
    fun startFailureEndsSession() {
        tunnel.failWith = IllegalStateException("foreground refused")
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))

        assertEquals(1, session.ended)
        assertEquals("Could not start the test: foreground refused", vm.error.value)
        assertEquals(Screen.Picker, vm.screen.value)
        assertNull(vm.reportUi.value)
        assertFalse(vm.starting.value)
        assertEquals(1, session.discards) // the aborted session leaves no history row
    }

    @Test
    fun startFailureWithFailingEndLeavesStopAvailable() {
        tunnel.failWith = IllegalStateException("foreground refused")
        session.endFails = true
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))

        assertTrue(vm.error.value!!.contains("press Stop"))
        assertTrue(session.state.value is SessionState.Running) // still running, so the user can stop it
        assertEquals(Screen.Session, vm.screen.value)

        session.endFails = false
        vm.stop()
        assertEquals(1, tunnel.stops)
        dispatcher.scheduler.advanceTimeBy(2_001)
        assertEquals(2, session.ended) // the failed attempt plus the orphan cleanup
        assertTrue(session.state.value is SessionState.Finished)
    }

    @Test
    fun stopEndsOrphanedRunningSession() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        vm.stop()
        assertEquals(0, session.ended) // grace period: the service may still end it
        dispatcher.scheduler.advanceTimeBy(2_001)
        assertEquals(1, session.ended)
    }

    @Test
    fun stopLeavesSessionAloneWhenServiceEndedIt() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        vm.stop()
        session.state.value = SessionState.Finished(report("com.example.app"))
        dispatcher.scheduler.advanceTimeBy(2_001)
        assertEquals(0, session.ended)
    }

    @Test
    fun openHistoryFailureShowsError() {
        val vm = vm(history = FakeHistory(failWith = IllegalStateException("bad json")))
        vm.openHistory()
        vm.openHistory(1L)
        assertEquals("This report could not be loaded.", vm.error.value)
        assertEquals(Screen.History, vm.screen.value)

        val missing = vm(history = FakeHistory())
        missing.openHistory()
        missing.openHistory(2L)
        assertEquals("This report no longer exists.", missing.error.value)
        assertEquals(Screen.History, missing.screen.value)
    }

    @Test
    fun emptyQuickEndedReportShowsErrorNotReport() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        session.state.value = SessionState.Finished(
            ReportBuilder.build("com.example.app", "Example", 1_000L, 2_000L, emptyList()),
        )
        assertEquals("Test could not start.", vm.error.value)
        assertEquals(Screen.Picker, vm.screen.value)
        assertNull(vm.reportUi.value)
        assertEquals(1, session.discards)
    }

    @Test
    fun quickStopShowsTheEmptyReportAndKeepsIt() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        vm.stop()
        session.state.value = SessionState.Finished(
            ReportBuilder.build("com.example.app", "Example", 1_000L, 2_000L, emptyList()),
        )

        assertNull(vm.error.value)
        assertEquals(Screen.Report, vm.screen.value)
        assertEquals(Verdict.INCONCLUSIVE, vm.reportUi.value!!.report.appVerdict)
        assertEquals(0, session.discards)
    }

    @Test
    fun stopIsForgottenOnceTheSessionFinished() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        vm.stop()
        session.state.value = SessionState.Finished(report("com.example.app"))
        vm.back()

        vm.start(AppInfo("com.example.app", "Example"))
        session.state.value = SessionState.Finished(
            ReportBuilder.build("com.example.app", "Example", 1_000L, 2_000L, emptyList()),
        )

        assertEquals("Test could not start.", vm.error.value)
        assertEquals(1, session.discards)
    }

    @Test
    fun leavingTheReportClearsPlaintext() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        session.plaintext["a.example/T2_UNTRUSTED_CA"] = "GET / HTTP/1.1\r\n".toByteArray()
        session.state.value = SessionState.Finished(report("com.example.app"))

        vm.back()

        assertTrue(session.plaintext.isEmpty())
    }

    @Test
    fun hidingFullContentClearsPlaintext() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        session.plaintext["a.example/T2_UNTRUSTED_CA"] = "GET / HTTP/1.1\r\n".toByteArray()
        session.state.value = SessionState.Finished(report("com.example.app"))
        vm.toggleReveal()
        assertEquals("GET / HTTP/1.1\r\n", vm.fullContent("a.example", ProbeCase.T2_UNTRUSTED_CA))

        vm.toggleReveal()

        assertTrue(session.plaintext.isEmpty())
        assertFalse(vm.reportUi.value!!.revealed)
        assertFalse(vm.reportUi.value!!.canReveal) // nothing left to show
        vm.toggleReveal()
        assertNull(vm.fullContent("a.example", ProbeCase.T2_UNTRUSTED_CA))
    }

    @Test
    fun secondStartWhileRunningIsIgnored() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        vm.start(AppInfo("com.other", "Other"))
        assertEquals(1, session.beginCount)
        assertEquals("com.example.app", session.begun!!.first)
    }

    @Test
    fun newSessionResetsReveal() {
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))
        session.state.value = SessionState.Finished(report("com.example.app"))
        vm.toggleReveal()
        assertTrue(vm.reportUi.value!!.revealed)

        vm.back()
        vm.start(AppInfo("com.example.app", "Example"))
        assertNull(vm.reportUi.value)
        session.state.value = SessionState.Finished(report("com.example.app"))
        assertFalse(vm.reportUi.value!!.revealed)
    }

    @Test
    fun selectedAppAndLabelSurviveInSavedState() {
        val saved = androidx.lifecycle.SavedStateHandle()
        val first = TrustProbeViewModel(FakeCatalog(emptyList()), session, FakeHistory(), tunnel, SELF, dispatcher, saved)
        first.select(AppInfo("com.example.app", "Example"))
        first.start(AppInfo("com.example.app", "Example"))
        val second = TrustProbeViewModel(FakeCatalog(emptyList()), session, FakeHistory(), tunnel, SELF, dispatcher, saved)
        assertEquals(AppInfo("com.example.app", "Example"), second.selected.value)
        assertEquals("Example", second.labelFor("com.example.app"))
        assertEquals("com.other", second.labelFor("com.other"))
    }

    @Test
    fun exportFileNameIsSanitised() {
        val r = report("com.ex ample/../x").copy(startedAt = 1_700_000_000_000L)
        assertEquals("trustprobe-com.ex_ample_.._x-20231114-2213.md", exportFileName(r, "md", ZoneId.of("UTC")))
    }

    @Test
    fun exportFileNameUsesPackageAndStartTime() {
        val r = report("com.example.app").copy(startedAt = 1_700_000_000_000L) // 2023-11-14 22:13:20 UTC
        assertEquals(
            "trustprobe-com.example.app-20231114-2213.md",
            exportFileName(r, "md", ZoneId.of("UTC")),
        )
    }

    private companion object {
        const val SELF = "io.github.leemikepop.trustprobe"

        fun report(pkg: String): Report = ReportBuilder.build(
            pkg, "Example", 1_000L, 2_000L,
            listOf(
                EngineEvent.Probed(
                    "a.example", 1_100L,
                    ProbeResult(ProbeCase.T2_UNTRUSTED_CA, OutcomeKind.ACCEPTED, null, null, "TLSv1.3", null, 5),
                ),
            ),
        )
    }
}
