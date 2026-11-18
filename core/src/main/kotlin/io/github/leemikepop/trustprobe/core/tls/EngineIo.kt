package io.github.leemikepop.trustprobe.core.tls

import java.io.IOException
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.Buffer
import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLEngineResult.HandshakeStatus
import javax.net.ssl.SSLEngineResult.Status

/**
 * Drives a server-mode [SSLEngine] over a blocking [Socket]. [initial] (bytes the caller already
 * read from the socket) is unwrapped before anything else is read.
 *
 * Throws [PeerClosed] when the peer ends the connection, [SocketTimeoutException] when it goes
 * quiet, [IllegalStateException] ("closed locally") when our side closed the socket, and the
 * engine's own [javax.net.ssl.SSLException]s (e.g. a received fatal alert).
 */
internal class EngineIo(private val engine: SSLEngine, private val socket: Socket, initial: ByteArray) {
    /** The peer ended the connection: EOF, reset, or close_notify. */
    class PeerClosed(message: String) : Exception(message)

    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()
    private val noData = ByteBuffer.allocate(0)
    private var netIn = ByteBuffer.allocate(maxOf(initial.size, engine.session.packetBufferSize))
        .apply { put(initial); flipBuffer() } // kept in read mode between operations
    private var netOut = ByteBuffer.allocate(engine.session.packetBufferSize)
    private var appIn = ByteBuffer.allocate(engine.session.applicationBufferSize)
    private var deadlineNanos: Long? = null
    private var wroteAny = false

    /** True once we sent our flight (with the certificate) and the engine is waiting for the peer. */
    var flightSent = false
        private set

    /** Returns once the handshake has completed. [timeoutMs] bounds each wait for the peer. */
    fun handshake(timeoutMs: Long) {
        socket.soTimeout = timeoutMs.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
        engine.beginHandshake()
        while (true) {
            val result = when (engine.handshakeStatus) {
                HandshakeStatus.NEED_TASK -> { runTasks(); continue }
                HandshakeStatus.NEED_WRAP -> wrap()
                HandshakeStatus.NEED_UNWRAP, HandshakeStatus.NEED_UNWRAP_AGAIN -> {
                    if (wroteAny) flightSent = true
                    unwrap().also { if (it.status == Status.CLOSED) throw PeerClosed("close_notify during handshake") }
                }
                else -> return // FINISHED or NOT_HANDSHAKING
            }
            if (result.handshakeStatus == HandshakeStatus.FINISHED) return
        }
    }

    /**
     * Returns the plaintext of the first unwrap that yields application data (at most [cap] bytes),
     * if it arrives within [timeoutMs]. Post-handshake messages we must send (TLS 1.3
     * NewSessionTicket) are flushed but are not data from the peer.
     */
    fun firstData(timeoutMs: Long, cap: Int): ByteArray {
        deadlineNanos = System.nanoTime() + timeoutMs * 1_000_000
        while (true) {
            // The unwrap that completed the handshake may already have produced data.
            if (appIn.position() > 0) return appIn.array().copyOf(minOf(appIn.position(), cap))
            when (engine.handshakeStatus) {
                HandshakeStatus.NEED_TASK -> { runTasks(); continue }
                HandshakeStatus.NEED_WRAP -> {
                    // Failing to send a ticket must not hide a request that is already buffered.
                    try { wrap() } catch (_: PeerClosed) { }
                    continue
                }
                else -> Unit
            }
            if (unwrap().status == Status.CLOSED) throw PeerClosed("close_notify after handshake")
        }
    }

    private fun runTasks() {
        while (true) (engine.delegatedTask ?: return).run()
    }

    /** Unwraps one record, reading from the socket as needed. Returns an OK or CLOSED result. */
    private fun unwrap(): SSLEngineResult {
        while (true) {
            val result = engine.unwrap(netIn, appIn)
            when (result.status) {
                Status.BUFFER_UNDERFLOW -> readMore()
                Status.BUFFER_OVERFLOW -> appIn = appIn.grown(engine.session.applicationBufferSize)
                else -> return result
            }
        }
    }

    private fun wrap(): SSLEngineResult {
        while (true) {
            netOut.clearBuffer()
            val result = engine.wrap(noData, netOut)
            when (result.status) {
                Status.BUFFER_OVERFLOW -> netOut = ByteBuffer.allocate(netOut.capacity() + engine.session.packetBufferSize)
                Status.CLOSED -> error("engine closed its outbound side")
                else -> { flush(); return result }
            }
        }
    }

    private fun flush() {
        if (netOut.position() == 0) return
        try {
            output.write(netOut.array(), 0, netOut.position())
            output.flush()
        } catch (e: IOException) {
            throw closed(e, "write failed")
        }
        wroteAny = true
    }

    /** A failed socket call is the peer's doing unless we closed the socket ourselves. */
    private fun closed(e: IOException, fallback: String): Exception =
        if (socket.isClosed) IllegalStateException("closed locally", e) else PeerClosed(e.message ?: fallback)

    private fun readMore() {
        netIn.compact()
        if (!netIn.hasRemaining()) netIn = netIn.grown(engine.session.packetBufferSize)
        deadlineNanos?.let { deadline ->
            val leftMs = (deadline - System.nanoTime()) / 1_000_000
            if (leftMs <= 0) throw SocketTimeoutException("no application data in time")
            socket.soTimeout = leftMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        }
        val n = try {
            input.read(netIn.array(), netIn.arrayOffset() + netIn.position(), netIn.remaining())
        } catch (e: SocketTimeoutException) {
            throw e
        } catch (e: IOException) {
            throw closed(e, "connection reset")
        }
        if (n < 0) throw PeerClosed("EOF")
        netIn.advance(n)
        netIn.flipBuffer()
    }
}

/** A buffer in write mode with [extra] more capacity, holding the same bytes. */
private fun ByteBuffer.grown(extra: Int): ByteBuffer {
    val bigger = ByteBuffer.allocate(capacity() + extra)
    flipBuffer()
    return bigger.put(this)
}

// Called through Buffer: ByteBuffer's covariant overrides (Java 9+) are absent on older Android.
private fun Buffer.flipBuffer() { flip() }
private fun Buffer.clearBuffer() { clear() }
private fun Buffer.advance(n: Int) { position(position() + n) }
