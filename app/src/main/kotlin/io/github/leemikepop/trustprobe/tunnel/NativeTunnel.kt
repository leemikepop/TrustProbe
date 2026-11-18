package io.github.leemikepop.trustprobe.tunnel

import hev.htproxy.TProxyService
import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import java.io.File

/** The only place that touches native code: writes the hev config and starts / stops the tunnel. */
object NativeTunnel {
    @Volatile private var config: File? = null

    /** Writes `hev.yaml` into [dir] and starts hev on the tun [fd]. Throws if hev refuses to start. */
    fun start(dir: File, socksPort: Int, credentials: Socks5Credentials, fd: Int) {
        val file = File(dir, "hev.yaml")
        file.writeText(HevConfig.render(socksPort, credentials))
        config = file
        check(TProxyService.TProxyStartService(file.absolutePath, fd)) { "hev-socks5-tunnel did not start" }
    }

    /** Stops hev, waits for its thread and deletes the config (it holds the SOCKS5 password). */
    fun stop() {
        TProxyService.TProxyStopService()
        config?.delete()
        config = null
    }
}
