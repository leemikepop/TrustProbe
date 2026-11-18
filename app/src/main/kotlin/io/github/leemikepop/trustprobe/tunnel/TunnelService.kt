package io.github.leemikepop.trustprobe.tunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import io.github.leemikepop.trustprobe.MainActivity
import io.github.leemikepop.trustprobe.TrustProbeApp
import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import io.github.leemikepop.trustprobe.session.SessionState
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Per-app VPN: only the app under test is routed into the tun, which hev-socks5-tunnel turns into
 * SOCKS5 connections to the probe engine. Runs as a foreground service (type `systemExempted`,
 * which VPN apps qualify for) so the session survives while the user is in the app under test.
 *
 * Every end path (time limit, stop action, [onRevoke], target uninstalled, [onDestroy]) goes
 * through [finish]: stop hev, close the tun fd, then end the session. All of it runs on the
 * main thread.
 */
class TunnelService : VpnService() {
    private class Tunnel(val pfd: ParcelFileDescriptor, val target: String)

    private val main = Handler(Looper.getMainLooper())
    private val timeLimit = Runnable { finish("time limit reached") }
    private var tunnel: Tunnel? = null
    private var receiverRegistered = false

    private val packageRemoved = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val pkg = intent.data?.schemeSpecificPart
            val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            if (!replacing && pkg != null && pkg == tunnel?.target) finish("app under test was uninstalled")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> begin(intent)
            ACTION_STOP -> finish("stopped by user")
            else -> if (tunnel == null) stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        finish("VPN permission revoked")
    }

    override fun onDestroy() {
        finish("service destroyed")
        super.onDestroy()
    }

    private fun begin(intent: Intent) {
        val target = intent.getStringExtra(EXTRA_PACKAGE)
        val port = intent.getIntExtra(EXTRA_PORT, 0)
        val user = intent.getStringExtra(EXTRA_USERNAME)
        val pass = intent.getStringExtra(EXTRA_PASSWORD)
        val durationSec = intent.getIntExtra(EXTRA_DURATION, 0)
        if (tunnel != null) {
            Log.w(TAG, "session already running; ignoring start for $target")
            return
        }
        val running = controller().state.value as? SessionState.Running
        val endsAt = running?.endsAt ?: (System.currentTimeMillis() + durationSec * 1_000L)
        goForeground(target.orEmpty(), endsAt)
        if (target == null || port == 0 || user == null || pass == null || durationSec <= 0) {
            finish("invalid start request")
            return
        }

        val dns = upstreamDns()
        val pfd = try {
            Builder()
                .setSession("TrustProbe: $target")
                .addAddress(HevConfig.IPV4, 32)
                .addAddress(HevConfig.IPV6, 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(dns)
                .setMtu(HevConfig.MTU)
                .addAllowedApplication(target)
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "could not build the VPN for $target", e)
            null
        }
        if (pfd == null) {
            finish("VPN not established (not prepared, or target missing)")
            return
        }
        tunnel = Tunnel(pfd, target)
        try {
            NativeTunnel.start(cacheDir, port, Socks5Credentials(user, pass), pfd.fd)
        } catch (e: Exception) {
            Log.e(TAG, "hev failed to start", e)
            finish("tunnel failed to start")
            return
        }
        registerPackageRemoved()
        main.postDelayed(timeLimit, (endsAt - System.currentTimeMillis()).coerceAtLeast(0))
        Log.i(TAG, "session running for $target via SOCKS5 port $port, DNS ${dns.hostAddress}")
    }

    /** Stops hev, closes the tun fd, then ends the session. Idempotent. */
    private fun finish(reason: String) {
        main.removeCallbacks(timeLimit)
        if (receiverRegistered) {
            unregisterReceiver(packageRemoved)
            receiverRegistered = false
        }
        val t = tunnel
        tunnel = null
        if (t != null) {
            NativeTunnel.stop()
            runCatching { t.pfd.close() }
        }
        val controller = controller()
        if (controller.state.value is SessionState.Running) {
            controller.end()
            Log.i(TAG, "session ended: $reason")
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun controller() = (application as TrustProbeApp).sessionController

    /** The first IPv4 DNS server of the network that is active before the VPN comes up. */
    private fun upstreamDns(): InetAddress {
        val cm = getSystemService(ConnectivityManager::class.java)
        val props = cm.activeNetwork?.let(cm::getLinkProperties)
        return props?.dnsServers?.firstOrNull { it is Inet4Address } ?: InetAddress.getByName(FALLBACK_DNS)
    }

    private fun registerPackageRemoved() {
        val filter = IntentFilter(Intent.ACTION_PACKAGE_REMOVED).apply { addDataScheme("package") }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(packageRemoved, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(packageRemoved, filter)
        }
        receiverRegistered = true
    }

    /**
     * An ongoing notification with a countdown to [endsAt] and a stop action. If notifications are
     * denied the service still runs in the foreground; only the notification is hidden.
     */
    private fun goForeground(target: String, endsAt: Long) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Test session", NotificationManager.IMPORTANCE_LOW),
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, TunnelService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Testing $target")
            .setContentText("Use the app now; the test stops automatically.")
            .setOngoing(true)
            .setWhen(endsAt)
            .setShowWhen(true)
            .setUsesChronometer(true)
            .setChronometerCountDown(true)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .build()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: RuntimeException) {
            // systemExempted needs VPN consent; the caller ran VpnService.prepare, so this should
            // not happen. Keep going: the system still binds an established VPN service.
            Log.e(TAG, "could not enter the foreground", e)
        }
    }

    companion object {
        private const val TAG = "TrustProbe"
        private const val ACTION_START = "io.github.leemikepop.trustprobe.action.START"
        private const val ACTION_STOP = "io.github.leemikepop.trustprobe.action.STOP"
        private const val EXTRA_PACKAGE = "package"
        private const val EXTRA_PORT = "port"
        private const val EXTRA_USERNAME = "username"
        private const val EXTRA_PASSWORD = "password"
        private const val EXTRA_DURATION = "durationSec"
        private const val CHANNEL_ID = "session"
        private const val NOTIFICATION_ID = 1
        private const val FALLBACK_DNS = "1.1.1.1"

        /**
         * Starts the VPN for [packageName] into the engine at [socksPort]. The caller has already
         * handled `VpnService.prepare` and begun the session on the controller.
         */
        fun start(
            context: Context,
            packageName: String,
            socksPort: Int,
            credentials: Socks5Credentials,
            durationSec: Int,
        ) {
            val intent = Intent(context, TunnelService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_PACKAGE, packageName)
                .putExtra(EXTRA_PORT, socksPort)
                .putExtra(EXTRA_USERNAME, credentials.username)
                .putExtra(EXTRA_PASSWORD, credentials.password)
                .putExtra(EXTRA_DURATION, durationSec)
            context.startForegroundService(intent)
        }

        /** Ends the running session (no-op if none). */
        fun stop(context: Context) {
            context.startService(Intent(context, TunnelService::class.java).setAction(ACTION_STOP))
        }
    }
}
