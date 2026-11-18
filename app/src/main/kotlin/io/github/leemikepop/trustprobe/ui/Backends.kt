package io.github.leemikepop.trustprobe.ui

import android.content.Context
import android.content.Intent
import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.report.Report
import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import io.github.leemikepop.trustprobe.data.RoomSessionStore
import io.github.leemikepop.trustprobe.data.SessionDao
import io.github.leemikepop.trustprobe.data.SessionEntity
import io.github.leemikepop.trustprobe.session.SessionController
import io.github.leemikepop.trustprobe.session.SessionState
import io.github.leemikepop.trustprobe.tunnel.TunnelService
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

/** Production adapters for the ViewModel's interfaces. */
class ControllerGateway(private val c: SessionController) : SessionGateway {
    override val state: StateFlow<SessionState> get() = c.state
    override val liveEvents: StateFlow<List<EngineEvent>> get() = c.liveEvents
    override val credentials: Socks5Credentials? get() = c.credentials
    override val plaintext: Map<String, ByteArray> get() = c.plaintext
    override fun begin(packageName: String, appLabel: String, durationSec: Int) =
        c.begin(packageName, appLabel, durationSec)
    override fun end(): Report = c.end()
}

class RoomHistory(private val dao: SessionDao, private val store: RoomSessionStore) : HistorySource {
    override fun sessions(): Flow<List<SessionEntity>> = dao.sessions()
    override suspend fun report(id: Long): Report? = store.report(id)
}

class ServiceTunnelLauncher(private val appContext: Context) : TunnelLauncher {
    override fun start(packageName: String, socksPort: Int, credentials: Socks5Credentials, durationSec: Int) =
        TunnelService.start(appContext, packageName, socksPort, credentials, durationSec)

    override fun stop() = TunnelService.stop(appContext)
}

class PackageManagerCatalog(private val context: Context) : AppCatalog {
    override suspend fun launchableApps(): List<AppInfo> {
        val pm = context.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(launcher, 0)
            .map { AppInfo(it.activityInfo.packageName, it.loadLabel(pm).toString()) }
            .distinctBy { it.packageName }
    }
}
