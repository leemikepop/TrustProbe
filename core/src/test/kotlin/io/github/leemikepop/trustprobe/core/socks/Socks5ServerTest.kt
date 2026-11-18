package io.github.leemikepop.trustprobe.core.socks

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean
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
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val creds = Socks5Credentials("user", "secret")
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
    ): Int = Socks5Server(tcp, policy, scope, creds).also { server = it }.start()

    private fun open(port: Int): Socket =
        Socket("127.0.0.1", port).track().also { it.soTimeout = 3000 }

    /** Offers user/pass, authenticates, returns the auth status byte pair. */
    private fun auth(s: Socket, user: String, pass: String): ByteArray {
        val out = s.getOutputStream()
        val inp = DataInputStream(s.getInputStream())
        out.write(byteArrayOf(5, 1, 2))
        val sel = ByteArray(2).also(inp::readFully)
        assertArrayEquals(byteArrayOf(5, 2), sel)
        val u = user.toByteArray()
        val p = pass.toByteArray()
        out.write(byteArrayOf(1, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p)
        return ByteArray(2).also(inp::readFully)
    }

    private fun authed(port: Int): Socket = open(port).also {
        assertArrayEquals(byteArrayOf(1, 0), auth(it, creds.username, creds.password))
    }

    private fun portBytes(p: Int) = byteArrayOf((p shr 8).toByte(), p.toByte())

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
        val s = authed(startServer())
        s.getOutputStream().write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1) + portBytes(echo.localPort))
        val inp = DataInputStream(s.getInputStream())
        val rep = ByteArray(10).also(inp::readFully)
        assertEquals(0, rep[1].toInt())
        s.getOutputStream().write("ping".toByteArray())
        val buf = ByteArray(4).also(inp::readFully)
        assertEquals("ping", String(buf))
    }

    @Test
    fun noAuthIsRejected() {
        val s = open(startServer())
        s.getOutputStream().write(byteArrayOf(5, 1, 0))
        val sel = ByteArray(2).also(DataInputStream(s.getInputStream())::readFully)
        assertArrayEquals(byteArrayOf(5, 0xFF.toByte()), sel)
        assertEquals(-1, s.getInputStream().read())
    }

    @Test
    fun wrongPasswordIsRejected() {
        val s = open(startServer())
        assertArrayEquals(byteArrayOf(1, 1), auth(s, "user", "wrong"))
        assertEquals(-1, s.getInputStream().read())
    }

    @Test
    fun correctCredentialsConnect() {
        val s = authed(startServer())
        s.getOutputStream().write(byteArrayOf(5, 2, 0, 1, 127, 0, 0, 1, 0, 80)) // BIND: any reply proves auth passed
        val rep = ByteArray(10).also(DataInputStream(s.getInputStream())::readFully)
        assertEquals(7, rep[1].toInt())
    }

    private fun associate(port: Int): InetSocketAddress {
        val ctl = authed(port)
        ctl.getOutputStream().write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
        val rep = ByteArray(10).also(DataInputStream(ctl.getInputStream())::readFully)
        assertEquals(0, rep[1].toInt())
        val relayPort = ((rep[8].toInt() and 0xFF) shl 8) or (rep[9].toInt() and 0xFF)
        return InetSocketAddress("127.0.0.1", relayPort)
    }

    private fun startUdpEcho(): InetSocketAddress {
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
        return InetSocketAddress("127.0.0.1", echo.localPort)
    }

    @Test
    fun udpAssociateRelaysAndDropsByPolicy() {
        val echoAddr = startUdpEcho()
        val allow = AtomicBoolean(true)
        val relay = associate(startServer(policy = { allow.get() }))

        val client = DatagramSocket().track()
        val wrapped = Socks5Codec.encodeUdp(echoAddr, "hello".toByteArray(), 5)

        client.soTimeout = 3000
        client.send(DatagramPacket(wrapped, wrapped.size, relay))
        val rb = ByteArray(1500)
        val rp = DatagramPacket(rb, rb.size)
        client.receive(rp)
        val parsed = Socks5Codec.parseUdp(rb, rp.length)!!
        assertEquals(echoAddr, parsed.dst)
        assertEquals("hello", String(parsed.payload))

        allow.set(false)
        client.soTimeout = 1000
        client.send(DatagramPacket(wrapped, wrapped.size, relay))
        assertThrows(SocketTimeoutException::class.java) { client.receive(DatagramPacket(rb, rb.size)) }
    }

    @Test
    fun udpFromOtherEndpointIsDropped() {
        val echoAddr = startUdpEcho()
        val relay = associate(startServer())
        val wrapped = Socks5Codec.encodeUdp(echoAddr, "x".toByteArray(), 1)
        val rb = ByteArray(1500)

        val first = DatagramSocket().track().also { it.soTimeout = 3000 }
        first.send(DatagramPacket(wrapped, wrapped.size, relay))
        first.receive(DatagramPacket(rb, rb.size)) // endpoint now locked

        val other = DatagramSocket().track().also { it.soTimeout = 1000 }
        other.send(DatagramPacket(wrapped, wrapped.size, relay))
        assertThrows(SocketTimeoutException::class.java) { other.receive(DatagramPacket(rb, rb.size)) }

        first.send(DatagramPacket(wrapped, wrapped.size, relay)) // locked endpoint still works
        first.receive(DatagramPacket(rb, rb.size))
    }

    @Test
    fun unsupportedCommandReplies07() {
        val s = authed(startServer())
        s.getOutputStream().write(byteArrayOf(5, 2, 0, 1, 127, 0, 0, 1, 0, 80)) // BIND
        val rep = ByteArray(10).also(DataInputStream(s.getInputStream())::readFully)
        assertEquals(7, rep[1].toInt())
    }

    @Test
    fun throwingHandlerClosesOnlyThatClient() {
        val port = startServer(tcp = { _, _ -> error("boom") })
        val s = authed(port)
        s.getOutputStream().write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, 0, 80))
        DataInputStream(s.getInputStream()).readFully(ByteArray(10))
        assertEquals(-1, s.getInputStream().read())
        authed(port) // server still accepts
    }

    @Test
    fun startTwiceFailsAndStopIsIdempotent() {
        val srv = Socks5Server({ c, _ -> c.close() }, { true }, scope, creds).also { server = it }
        srv.start()
        assertThrows(IllegalStateException::class.java) { srv.start() }
        srv.stop()
        srv.stop()
    }
}
