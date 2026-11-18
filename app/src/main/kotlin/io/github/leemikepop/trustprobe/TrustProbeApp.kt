package io.github.leemikepop.trustprobe

import android.app.Application
import io.github.leemikepop.trustprobe.core.ProbeEngine
import io.github.leemikepop.trustprobe.session.InMemorySessionStore
import io.github.leemikepop.trustprobe.session.SessionController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob

/** Owns the single [SessionController] shared by the UI and [tunnel.TunnelService]. */
class TrustProbeApp : Application() {
    private val engineScope = CoroutineScope(SupervisorJob())

    val sessionController = SessionController(
        engineFactory = { onEvent, onPlaintext -> ProbeEngine(engineScope, onEvent, onPlaintext) },
        clock = System::currentTimeMillis,
        store = InMemorySessionStore(),
    )
}
