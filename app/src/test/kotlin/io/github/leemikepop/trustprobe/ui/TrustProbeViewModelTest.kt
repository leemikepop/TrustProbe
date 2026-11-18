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

        override fun begin(packageName: String, appLabel: String, durationSec: Int): Int {
            begun = Triple(packageName, appLabel, durationSec)
            credentials = Socks5Credentials("u", "p")
            state.value = SessionState.Running(packageName, 1_000L + durationSec * 1_000L)
            return 4242
        }

        override fun end(): Report {
            ended++
            return report("com.example.app").also { state.value = SessionState.Finished(it) }
        }
    }

    private class FakeHistory(val rows: List<SessionEntity> = emptyList(), val reports: Map<Long, Report> = emptyMap()) :
        HistorySource {
        override fun sessions(): Flow<List<SessionEntity>> = flowOf(rows)
        override suspend fun report(id: Long) = reports[id]
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
        assertNull(vm.fullContent("a.example", ProbeCase.T2_UNTRUSTED_CA)) // plaintext still in memory, still hidden
    }

    @Test
    fun startFailureEndsSession() {
        tunnel.failWith = IllegalStateException("foreground refused")
        val vm = vm()
        vm.start(AppInfo("com.example.app", "Example"))

        assertEquals(1, session.ended)
        assertEquals("foreground refused", vm.error.value)
        assertEquals(Screen.Picker, vm.screen.value)
        assertNull(vm.reportUi.value)
        assertFalse(vm.starting.value)
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
