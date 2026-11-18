package io.github.leemikepop.trustprobe.e2e

import android.content.Context
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
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Runs a real TrustProbe session against the `:testbed` app (must already be installed:
 * `./gradlew :testbed:installDebug`) and checks the four expected verdicts.
 * The expected hosts and verdicts are repeated here on purpose; the test does not depend on `:testbed`.
 */
class TestbedVerdictsTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private lateinit var controller: SessionController
    private var begun = false

    @Before
    fun setUp() {
        val pm = shell("pm path $TESTBED")
        assertTrue("testbed $TESTBED is not installed; run ./gradlew :testbed:installDebug first", pm.contains("package:"))
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
        // Give the VPN a moment to come up before the app starts connecting (it retries anyway).
        SystemClock.sleep(1_500)
        shell("am start -n $TESTBED/.MainActivity --ez autorun true")

        val deadline = SystemClock.elapsedRealtime() + WAIT_MS
        while (SystemClock.elapsedRealtime() < deadline && !allHostsDone(controller.liveEvents.value)) {
            SystemClock.sleep(POLL_MS)
        }
        val events = controller.liveEvents.value
        if (!allHostsDone(events)) {
            fail("hosts not done within ${WAIT_MS / 1000} s; events:\n" + events.joinToString("\n"))
        }

        TunnelService.stop(context)
        val stopDeadline = SystemClock.elapsedRealtime() + STOP_WAIT_MS
        while (SystemClock.elapsedRealtime() < stopDeadline && controller.state.value !is SessionState.Finished) {
            SystemClock.sleep(POLL_MS)
        }
        val finished = controller.state.value as? SessionState.Finished
        assertNotNull("session did not finish within ${STOP_WAIT_MS / 1000} s of stopping the tunnel", finished)
        val report = finished!!.report
        val md = ReportRenderer.markdown(report)

        fun check(message: String, ok: Boolean) {
            if (!ok) fail("$message\n\n$md")
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
        const val POLL_MS = 500L
    }
}
