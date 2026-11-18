package io.github.leemikepop.trustprobe

import android.app.Application
import io.github.leemikepop.trustprobe.core.ProbeEngine
import io.github.leemikepop.trustprobe.data.RoomSessionStore
import io.github.leemikepop.trustprobe.data.SessionDao
import io.github.leemikepop.trustprobe.data.TrustProbeDatabase
import io.github.leemikepop.trustprobe.session.SessionController
import io.github.leemikepop.trustprobe.tunnel.NativeTunnel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob

/** Owns the single [SessionController] shared by the UI and [tunnel.TunnelService]. */
class TrustProbeApp : Application() {
    private val engineScope = CoroutineScope(SupervisorJob())

    // Lazy: the database needs the base context, which does not exist yet at construction time.
    val sessionDao: SessionDao by lazy { TrustProbeDatabase.create(this).sessionDao() }

    val sessionStore: RoomSessionStore by lazy { RoomSessionStore(sessionDao) }

    val sessionController: SessionController by lazy {
        SessionController(
            engineFactory = { onEvent, onPlaintext -> ProbeEngine(engineScope, onEvent, onPlaintext) },
            clock = System::currentTimeMillis,
            store = sessionStore,
        )
    }

    override fun onCreate() {
        super.onCreate()
        // A fresh process has no tunnel running, so any hev.yaml is stale (and holds a password).
        NativeTunnel.deleteStaleConfig(cacheDir)
    }
}
