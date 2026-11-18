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
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Per-app VPN: only the app under test is routed into the tun, which hev-socks5-tunnel turns into
 * SOCKS5 connections to the probe engine. Runs as a foreground service (type `systemExempted`,
 * which VPN apps qualify for) so the session survives while the user is in the app under test.
 *
 * Every end path (time limit, stop action, [onRevoke], target uninstalled, hev dying, [onDestroy])
 * goes through [finish]: stop hev, close the tun fd, then end the session if this instance owns
 * it. Lifecycle callbacks, the receiver and the Handler run on the main thread; [onRevoke] arrives
 * on a binder thread and is posted to the main thread, so all of this state is main-thread only.
 */
class TunnelService : VpnService() {
    private class Tunnel(val pfd: ParcelFileDescriptor, val target: String)

    private val main = Handler(Looper.getMainLooper())
    private val timeLimit = Runnable { finish("time limit reached") }
    private val hevCheck = Runnable {
        if (tunnel != null && !NativeTunnel.isRunning()) finish("tunnel failed to start (hev exited)")
    }
    private var tunnel: Tunnel? = null
    private var receiverRegistered = false

    /** True once this instance has validated a start against the controller's running session. */
    private var ownsSession = false

    /** Set by [finish]; a finished instance never starts another tunnel. */
    private var finished = false

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
        // Called on a binder thread: hand it to the main thread like every other end path.
        main.post { finish("VPN permission revoked") }
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
        val controller = controller()
        val running = controller.state.value as? SessionState.Running
        val endsAt = running?.endsAt ?: (System.currentTimeMillis() + durationSec * 1_000L)
        // startForegroundService() obliges us to call startForeground() on every start request.
        if (tunnel != null) {
            goForeground(target.orEmpty(), endsAt)
            Log.w(TAG, "session already running; ignoring start for $target")
            return
        }
        val credentials = if (user != null && pass != null) Socks5Credentials(user, pass) else null
        val refusal = when {
            finished -> "start after finish ignored"
            running?.packageName != target || controller.socksPort != port || controller.credentials != credentials ->
                "start request does not match the running session"
            durationSec <= 0 -> "invalid duration"
            else -> null
        }
        // Claim the session before going foreground, so a refused foreground still ends it.
        ownsSession = refusal == null
        if (!goForeground(target.orEmpty(), endsAt)) return
        if (refusal != null || target == null || credentials == null) {
            finish(refusal ?: "invalid start request")
            return
        }

        val net = upstreamNetwork()
        val builder = Builder()
            .setSession("TrustProbe: $target")
            .setMetered(false)
            .addAddress(HevConfig.IPV4, 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(net.dns)
            .setMtu(HevConfig.MTU)
        if (net.routeIpv6) builder.addAddress(HevConfig.IPV6, 128).addRoute("::", 0)
        val pfd = try {
            builder.addAllowedApplication(target).establish()
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
            NativeTunnel.start(cacheDir, port, credentials, pfd.fd)
        } catch (e: Exception) {
            Log.e(TAG, "hev failed to start", e)
            finish("tunnel failed to start")
            return
        }
        registerPackageRemoved()
        main.postDelayed(timeLimit, (endsAt - System.currentTimeMillis()).coerceAtLeast(0))
        main.postDelayed(hevCheck, HEV_CHECK_DELAY_MS)
        Log.i(TAG, "session running for $target via SOCKS5 port $port")
        Log.i(TAG, "upstream DNS ${net.dns.hostAddress}, IPv6 routed: ${net.routeIpv6}")
    }

    /** Stops hev, closes the tun fd, then ends the session if this instance owns it. Idempotent. */
    private fun finish(reason: String) {
        finished = true
        main.removeCallbacks(timeLimit)
        main.removeCallbacks(hevCheck)
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
        if (ownsSession) {
            ownsSession = false
            val controller = controller()
            if (controller.state.value is SessionState.Running) controller.end()
            Log.i(TAG, "session ended: $reason")
        } else {
            Log.i(TAG, "tunnel service stopping without a session: $reason")
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun controller() = (application as TrustProbeApp).sessionController

    private class Upstream(val dns: InetAddress, val routeIpv6: Boolean)

    /**
     * Reads the network that is active before the VPN comes up: its first IPv4 DNS server (or
     * [FALLBACK_DNS]) and whether it really has IPv6 ([Ipv6Policy]).
     */
    private fun upstreamNetwork(): Upstream {
        val cm = getSystemService(ConnectivityManager::class.java)
        val props = cm.activeNetwork?.let(cm::getLinkProperties)
        val dns = props?.dnsServers?.firstOrNull { it is Inet4Address } ?: InetAddress.getByName(FALLBACK_DNS)
        val ipv6 = props != null && Ipv6Policy.routeIpv6(
            hasIpv6DefaultRoute = props.routes.any { it.isDefaultRoute && it.destination.address is Inet6Address },
            addresses = props.linkAddresses.map { it.address },
        )
        return Upstream(dns, ipv6)
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
     * denied the service still runs in the foreground; only the notification is hidden. Returns
     * false (after finishing) if the system refuses the foreground service.
     */
    private fun goForeground(target: String, endsAt: Long): Boolean {
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
            // systemExempted is refused without VPN consent (VpnService.prepare not done), and a
            // VPN app that is not in the foreground gets shut down: end here instead.
            Log.e(TAG, "could not enter the foreground", e)
            finish("foreground service refused")
            return false
        }
        return true
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
        private const val HEV_CHECK_DELAY_MS = 1_500L

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
