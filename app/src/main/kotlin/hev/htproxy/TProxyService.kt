package hev.htproxy

/**
 * JNI binding for the unmodified hev-socks5-tunnel library. Its `hev-jni.c` registers these
 * natives on the class `hev/htproxy/TProxyService` in `JNI_OnLoad`, so the package and class name
 * must stay exactly as they are. Only [io.github.leemikepop.trustprobe.tunnel.NativeTunnel] calls it.
 */
object TProxyService {
    init {
        System.loadLibrary("hev-socks5-tunnel")
    }

    /** Starts the tunnel on its own native thread; false if it is already running or failed to start. */
    external fun TProxyStartService(configPath: String, fd: Int): Boolean

    /** Asks the tunnel to quit and joins its thread. */
    external fun TProxyStopService(): Boolean

    external fun TProxyIsRunning(): Boolean

    /** tx packets, tx bytes, rx packets, rx bytes. */
    external fun TProxyGetStats(): LongArray
}
