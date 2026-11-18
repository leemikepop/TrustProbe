package io.github.leemikepop.trustprobe.core.socks

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.concurrent.thread

object Relay {
    private const val CONNECT_TIMEOUT_MS = 10_000

    /**
     * Copies both directions until both ended (EOF propagates as shutdownOutput) or either
     * errors, then closes both sockets. Blocks the calling thread.
     */
    fun pipe(a: Socket, b: Socket) {
        val t = thread(isDaemon = true, name = "relay-b-to-a") { copy(b, a) }
        copy(a, b)
        t.join()
        closeQuietly(a)
        closeQuietly(b)
    }

    /** Connects to [dst], sends [prefix], then pipes. Closes [client] if the connect fails. */
    fun connectAndPipe(client: Socket, dst: InetSocketAddress, prefix: ByteArray = ByteArray(0)) {
        val upstream = Socket()
        try {
            upstream.connect(dst, CONNECT_TIMEOUT_MS)
            if (prefix.isNotEmpty()) upstream.getOutputStream().apply { write(prefix); flush() }
        } catch (e: IOException) {
            closeQuietly(upstream)
            closeQuietly(client)
            return
        }
        pipe(client, upstream)
    }

    private fun copy(from: Socket, to: Socket) {
        try {
            val input = from.getInputStream()
            val output = to.getOutputStream()
            val buf = ByteArray(16 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
                output.flush()
            }
            runCatching { to.shutdownOutput() }
        } catch (e: IOException) {
            closeQuietly(from)
            closeQuietly(to)
        }
    }

    private fun closeQuietly(s: Socket) {
        try { s.close() } catch (_: IOException) {}
    }
}
