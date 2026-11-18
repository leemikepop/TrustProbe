package io.github.leemikepop.trustprobe.tunnel

import hev.htproxy.TProxyService
import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import java.io.File

/** The only place that touches native code: writes the hev config and starts / stops the tunnel. */
object NativeTunnel {
    private const val CONFIG_NAME = "hev.yaml"

    @Volatile private var config: File? = null

    /** Writes `hev.yaml` into [dir] and starts hev on the tun [fd]. Throws if hev refuses to start. */
    fun start(dir: File, socksPort: Int, credentials: Socks5Credentials, fd: Int) {
        val file = File(dir, CONFIG_NAME)
        file.writeText(HevConfig.render(socksPort, credentials))
        config = file
        check(TProxyService.TProxyStartService(file.absolutePath, fd)) { "hev-socks5-tunnel did not start" }
    }

    /** False once hev's thread has exited (for instance after rejecting its config). */
    fun isRunning(): Boolean = TProxyService.TProxyIsRunning()

    /** Stops hev, waits for its thread and deletes the config (it holds the SOCKS5 password). */
    fun stop() {
        TProxyService.TProxyStopService()
        config?.delete()
        config = null
    }

    /** Removes a config left behind by a process that died mid-session. */
    fun deleteStaleConfig(dir: File) {
        File(dir, CONFIG_NAME).delete()
    }
}
