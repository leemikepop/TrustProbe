package io.github.leemikepop.trustprobe.e2e

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import io.github.leemikepop.trustprobe.TrustProbeApp
import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.ForwardReason
import io.github.leemikepop.trustprobe.core.probe.HostVerdict
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.Severity
import io.github.leemikepop.trustprobe.core.probe.Verdict
import io.github.leemikepop.trustprobe.core.report.ReportRenderer
import io.github.leemikepop.trustprobe.session.SessionController
import io.github.leemikepop.trustprobe.session.SessionState
import io.github.leemikepop.trustprobe.tunnel.TunnelService
import java.io.FileInputStream
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.Timeout

/**
 * Runs a real TrustProbe session against the `:testbed` app (must already be installed:
 * `./gradlew :testbed:installDebug`) and checks the four expected verdicts.
 * The expected hosts and verdicts are repeated here on purpose; the test does not depend on `:testbed`.
 */
class TestbedVerdictsTest {
    @get:Rule
    val timeout: Timeout = Timeout(4, TimeUnit.MINUTES)

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private lateinit var controller: SessionController
    private var begun = false
    private val notes = mutableListOf<String>()

    @Before
    fun setUp() {
        val pm = shell("pm path $TESTBED")
        assertTrue("testbed $TESTBED is not installed; run ./gradlew :testbed:installDebug first", pm.contains("package:"))
        shell("input keyevent KEYCODE_WAKEUP")
        shell("wm dismiss-keyguard")
        shell("svc power stayon true")
        shell("am force-stop $TESTBED")
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        assertEquals("VPN consent not granted", null, VpnService.prepare(context))
        controller = (context.applicationContext as TrustProbeApp).sessionController
    }

    @After
    fun tearDown() {
        runCatching { TunnelService.stop(context) }
        if (begun) runCatching { controller.end() }
        shell("am force-stop $TESTBED")
    }

    @Test
    fun testbedVerdicts() {
        val port = controller.begin(TESTBED, "Testbed", DURATION_SEC)
        begun = true
        TunnelService.start(context, TESTBED, port, checkNotNull(controller.credentials), DURATION_SEC)

        // Gate: the tunnel is up and the default network is validated (the testbed is one-shot).
        val gateDeadline = SystemClock.elapsedRealtime() + GATE_MS
        while (SystemClock.elapsedRealtime() < gateDeadline && !(TunnelService.tunnelUp.value && networkValidated())) {
            SystemClock.sleep(POLL_MS)
        }
        if (!TunnelService.tunnelUp.value) {
            failWith("tunnel not up within ${GATE_MS / 1000} s (session state ${controller.state.value})")
        }
        if (!networkValidated()) failWith("default network not VALIDATED within ${GATE_MS / 1000} s")

        var relaunches = 0
        var launchedAt = launchTestbed()
        val deadline = SystemClock.elapsedRealtime() + WAIT_MS
        while (!allHostsDone(controller.liveEvents.value)) {
            val state = controller.state.value
            if (state is SessionState.Finished) {
                failWith("session ended early\n\n${ReportRenderer.markdown(state.report)}")
            }
            val now = SystemClock.elapsedRealtime()
            if (now >= deadline) {
                failWith(
                    "hosts not done within ${WAIT_MS / 1000} s; state $state; events:\n" +
                        controller.liveEvents.value.joinToString("\n"),
                )
            }
            if (controller.liveEvents.value.isEmpty() && now - launchedAt > FIRST_EVENT_MS && relaunches < MAX_RELAUNCHES) {
                relaunches++
                notes += "no engine event ${FIRST_EVENT_MS / 1000} s after launch; relaunch $relaunches of $MAX_RELAUNCHES"
                shell("am force-stop $TESTBED")
                launchedAt = launchTestbed()
            }
            SystemClock.sleep(POLL_MS)
        }

        runCatching { TunnelService.stop(context) }
        val stopDeadline = SystemClock.elapsedRealtime() + STOP_WAIT_MS
        while (SystemClock.elapsedRealtime() < stopDeadline && controller.state.value !is SessionState.Finished) {
            SystemClock.sleep(POLL_MS)
        }
        val finished = controller.state.value as? SessionState.Finished
            ?: failWith("session did not finish within ${STOP_WAIT_MS / 1000} s of stopping the tunnel")
        val report = finished.report
        val md = ReportRenderer.markdown(report)

        fun check(message: String, ok: Boolean) {
            if (!ok) failWith("$message\n\n$md")
        }
        fun host(h: String): HostVerdict {
            val v = report.hosts.firstOrNull { it.host == h }
            check("no verdict for $h", v != null)
            return v!!
        }

        val com = host("example.com")
        check("example.com verdict ${com.verdict}", com.verdict == Verdict.PASS)
        check("example.com cases ${com.casesRun}", com.casesRun == listOf(ProbeCase.T2_UNTRUSTED_CA, ProbeCase.T1_SELF_SIGNED))

        val net = host("example.net")
        check("example.net verdict ${net.verdict}", net.verdict == Verdict.VULNERABLE)
        check("example.net severity ${net.severity}", net.severity == Severity.ACCEPTS_ANY_CERT)
        check("example.net cases ${net.casesRun}", net.casesRun == listOf(ProbeCase.T2_UNTRUSTED_CA, ProbeCase.T3_WRONG_HOST))

        val org = host("example.org")
        check("example.org verdict ${org.verdict}", org.verdict == Verdict.PASS)

        val www = host("www.example.com")
        check("www.example.com verdict ${www.verdict}", www.verdict == Verdict.PASS)

        // The report rebuilt from Room (what History shows) must match the live one.
        val app = context.applicationContext as TrustProbeApp
        val stored = runBlocking {
            val row = app.sessionDao.sessions().first()
                .firstOrNull { it.packageName == TESTBED && it.startedAt == report.startedAt }
            row?.let { app.sessionStore.report(it.id) }
        }
        check("no stored session for this run", stored != null)
        check("stored hosts differ: ${stored!!.hosts}", stored.hosts == report.hosts)
        check(
            "stored app verdict ${stored.appVerdict} (${stored.appReason})",
            stored.appVerdict == report.appVerdict && stored.appReason == report.appReason,
        )
        check("stored endedAt ${stored.endedAt} vs ${report.endedAt}", stored.endedAt == report.endedAt)
    }

    /** Starts the testbed, checks that it really came to the foreground, returns the launch time. */
    private fun launchTestbed(): Long {
        val out = shell("am start -W -n $TESTBED/.MainActivity --ez autorun true")
        if (out.contains("Error:") || out.contains("Warning: Activity not started")) {
            failWith("am start failed: $out")
        }
        val until = SystemClock.elapsedRealtime() + RESUMED_MS
        while (SystemClock.elapsedRealtime() < until) {
            val resumed = shell("dumpsys activity activities").lineSequence()
                .any { ("ResumedActivity" in it) && "$TESTBED/" in it }
            if (resumed) return SystemClock.elapsedRealtime()
            SystemClock.sleep(POLL_MS)
        }
        failWith("testbed MainActivity not resumed within ${RESUMED_MS / 1000} s; am start said: $out")
    }

    private fun networkValidated(): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    /** Fails with [message], the relaunch notes, and logcat / VPN diagnostics so CI logs explain it. */
    private fun failWith(message: String): Nothing {
        val logcat = runCatching {
            shell("logcat -d -v threadtime -s TrustProbe:* TrustProbeTestbed:*").lines().takeLast(300).joinToString("\n")
        }.getOrDefault("(logcat unavailable)")
        val vpn = runCatching {
            shell("dumpsys connectivity").lines().filter { it.contains("VPN", ignoreCase = true) }
                .take(80).joinToString("\n")
        }.getOrDefault("(dumpsys unavailable)")
        val text = buildString {
            append(message)
            if (notes.isNotEmpty()) append("\n\nrelaunches:\n").append(notes.joinToString("\n"))
            append("\n\n--- logcat (TrustProbe, TrustProbeTestbed) ---\n").append(logcat)
            append("\n\n--- dumpsys connectivity (VPN lines) ---\n").append(vpn)
        }
        fail(text)
        throw AssertionError(text) // unreachable; fail() throws
    }

    private fun allHostsDone(events: List<EngineEvent>): Boolean {
        val done = events.filterIsInstance<EngineEvent.Forwarded>()
            .filter { it.reason == ForwardReason.HOST_DONE }.map { it.host }.toSet()
        return done.containsAll(HOSTS)
    }

    /** Runs a shell command and reads its output to the end, so the command has actually run. */
    private fun shell(command: String): String {
        val pfd = instrumentation.uiAutomation.executeShellCommand(command)
        return FileInputStream(pfd.fileDescriptor).use { it.readBytes().decodeToString() }
    }

    private companion object {
        const val TESTBED = "io.github.leemikepop.trustprobe.testbed"
        val HOSTS = setOf("example.com", "example.net", "example.org", "www.example.com")
        const val DURATION_SEC = 120
        const val WAIT_MS = 90_000L
        const val STOP_WAIT_MS = 10_000L
        const val GATE_MS = 30_000L
        const val FIRST_EVENT_MS = 20_000L
        const val RESUMED_MS = 10_000L
        const val MAX_RELAUNCHES = 2
        const val POLL_MS = 500L
    }
}
