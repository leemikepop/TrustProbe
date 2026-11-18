package io.github.leemikepop.trustprobe.debug

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import io.github.leemikepop.trustprobe.TrustProbeApp
import io.github.leemikepop.trustprobe.core.report.ReportRenderer
import io.github.leemikepop.trustprobe.session.SessionController
import io.github.leemikepop.trustprobe.session.SessionState
import io.github.leemikepop.trustprobe.tunnel.TunnelService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Debug-only trigger. VPN consent must already be granted
 * (`adb shell appops set io.github.leemikepop.trustprobe ACTIVATE_VPN allow`), then:
 * `adb shell am start -n io.github.leemikepop.trustprobe/.debug.DebugSessionActivity
 *  --es package <pkg> --ei durationSec 120`.
 * Logs every engine event and, at the end, the Markdown report with tag `TrustProbe`.
 */
class DebugSessionActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pkg = intent.getStringExtra("package")
        val durationSec = intent.getIntExtra("durationSec", 120)
        when {
            pkg == null -> Log.w(TAG, "missing --es package")
            VpnService.prepare(this) != null -> Log.w(TAG, "VPN consent not granted")
            else -> runCatching { begin(pkg, durationSec) }.onFailure { Log.e(TAG, "could not begin", it) }
        }
        finish()
    }

    private fun begin(pkg: String, durationSec: Int) {
        val controller = (application as TrustProbeApp).sessionController
        val port = controller.begin(pkg, pkg, durationSec)
        TunnelService.start(this, pkg, port, checkNotNull(controller.credentials), durationSec)
        logUntilFinished(controller)
    }

    private fun logUntilFinished(controller: SessionController) {
        CoroutineScope(Dispatchers.Default).launch {
            var logged = 0
            val events = launch {
                controller.liveEvents.collect { list ->
                    list.drop(logged).forEach { Log.i(TAG, "event: $it") }
                    logged = list.size
                }
            }
            val finished = controller.state.first { it is SessionState.Finished } as SessionState.Finished
            events.cancelAndJoin()
            ReportRenderer.markdown(finished.report).lines().forEach { Log.i(TAG, "report| $it") }
        }
    }

    private companion object {
        const val TAG = "TrustProbe"
    }
}
