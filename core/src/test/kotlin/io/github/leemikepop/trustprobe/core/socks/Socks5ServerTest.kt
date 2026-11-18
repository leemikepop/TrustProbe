package io.github.leemikepop.trustprobe.core.socks

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import kotlin.concurrent.thread
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class Socks5ServerTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var server: Socks5Server? = null
    private val closeables = mutableListOf<AutoCloseable>()

    @After
    fun tearDown() {
        server?.stop()
        closeables.forEach { runCatching { it.close() } }
        scope.cancel()
    }

    private fun <T : AutoCloseable> T.track(): T = also { closeables += it }

    private fun startServer(
        tcp: TcpHandler = TcpHandler { c, d -> Relay.connectAndPipe(c, d) },
        policy: (InetSocketAddress) -> Boolean = { true },
    ): Int = Socks5Server(tcp, policy, scope).also { server = it }.start()

    @Test
    fun connectForwardsBytes() {
        val echo = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")).track()
        thread(isDaemon = true) {
            runCatching {
                echo.accept().use { s ->
                    val buf = ByteArray(4)
                    DataInputStream(s.getInputStream()).readFully(buf)
                    s.getOutputStream().write(buf)
                }
            }
        }
        val port = startServer()
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
        val s = Socket(proxy).track()
        s.soTimeout = 3000
        s.connect(InetSocketAddress("127.0.0.1", echo.localPort))
        s.getOutputStream().write("ping".toByteArray())
        val buf = ByteArray(4)
        DataInputStream(s.getInputStream()).readFully(buf)
        assertEquals("ping", String(buf))
    }

    @Test
    fun udpAssociateRelaysAndDropsByPolicy() {
        val echo = DatagramSocket(0, InetAddress.getByName("127.0.0.1")).track()
        thread(isDaemon = true) {
            runCatching {
                val b = ByteArray(1500)
                while (true) {
                    val p = DatagramPacket(b, b.size)
                    echo.receive(p)
                    echo.send(DatagramPacket(p.data, p.length, p.socketAddress))
                }
            }
        }
        val echoAddr = InetSocketAddress("127.0.0.1", echo.localPort)
        val allow = java.util.concurrent.atomic.AtomicBoolean(true)
        val port = startServer(policy = { allow.get() })

        val ctl = Socket("127.0.0.1", port).track()
        ctl.soTimeout = 3000
        val out = ctl.getOutputStream()
        val inp = DataInputStream(ctl.getInputStream())
        out.write(byteArrayOf(5, 1, 0))
        val greet = ByteArray(2)
        inp.readFully(greet)
        assertArrayEquals(byteArrayOf(5, 0), greet)
        out.write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
        val rep = ByteArray(10)
        inp.readFully(rep)
        assertEquals(0, rep[1].toInt())
        val relayPort = ((rep[8].toInt() and 0xFF) shl 8) or (rep[9].toInt() and 0xFF)
        val relayAddr = InetSocketAddress("127.0.0.1", relayPort)

        val client = DatagramSocket().track()
        val wrapped = Socks5Codec.encodeUdp(echoAddr, "hello".toByteArray(), 5)

        client.soTimeout = 3000
        client.send(DatagramPacket(wrapped, wrapped.size, relayAddr))
        val rb = ByteArray(1500)
        val rp = DatagramPacket(rb, rb.size)
        client.receive(rp)
        val parsed = Socks5Codec.parseUdp(rb, rp.length)!!
        assertEquals(echoAddr, parsed.dst)
        assertEquals("hello", String(parsed.payload))

        allow.set(false)
        client.soTimeout = 1000
        client.send(DatagramPacket(wrapped, wrapped.size, relayAddr))
        assertThrows(SocketTimeoutException::class.java) { client.receive(DatagramPacket(rb, rb.size)) }
    }

    @Test
    fun unsupportedCommandReplies07() {
        val port = startServer()
        val s = Socket("127.0.0.1", port).track()
        s.soTimeout = 3000
        val out = s.getOutputStream()
        val inp = DataInputStream(s.getInputStream())
        out.write(byteArrayOf(5, 1, 0))
        inp.readFully(ByteArray(2))
        out.write(byteArrayOf(5, 2, 0, 1, 127, 0, 0, 1, 0, 80)) // BIND
        val rep = ByteArray(10)
        inp.readFully(rep)
        assertEquals(7, rep[1].toInt())
    }

    @Test
    fun startTwiceFailsAndStopIsIdempotent() {
        val srv = Socks5Server({ c, _ -> c.close() }, { true }, scope).also { server = it }
        srv.start()
        assertThrows(IllegalStateException::class.java) { srv.start() }
        srv.stop()
        srv.stop()
    }
}
