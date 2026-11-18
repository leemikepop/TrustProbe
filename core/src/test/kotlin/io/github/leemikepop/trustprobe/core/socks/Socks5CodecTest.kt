package io.github.leemikepop.trustprobe.core.socks

import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class Socks5CodecTest {
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun parsesIpv4Connect() {
        val req = Socks5Codec.readRequest(
            ByteArrayInputStream(bytes(5, 1, 0, 1, 93, 184, 216, 34, 0x01, 0xBB))
        )
        assertEquals(Socks5Codec.CMD_CONNECT, req.cmd)
        assertEquals(InetAddress.getByAddress(bytes(93, 184, 216, 34)), req.dst.address)
        assertEquals(443, req.dst.port)
    }

    @Test
    fun parsesIpv6Connect() {
        val addr = ByteArray(16) { if (it == 15) 1 else 0 }
        val req = Socks5Codec.readRequest(
            ByteArrayInputStream(bytes(5, 1, 0, 4) + addr + bytes(0x1F, 0x90))
        )
        assertEquals(InetAddress.getByAddress(addr), req.dst.address)
        assertEquals(8080, req.dst.port)
    }

    @Test
    fun parsesDomainConnect() {
        val host = "localhost".toByteArray()
        val req = Socks5Codec.readRequest(
            ByteArrayInputStream(bytes(5, 1, 0, 3, host.size) + host + bytes(0, 80))
        )
        assertEquals("localhost", req.dst.hostName)
        assertEquals(80, req.dst.port)
    }

    @Test
    fun parsesUdpHeader() {
        val pkt = bytes(0, 0, 0, 1, 10, 0, 0, 1, 0x01, 0xBB) + "hi".toByteArray()
        val p = Socks5Codec.parseUdp(pkt, pkt.size)!!
        assertEquals(InetAddress.getByAddress(bytes(10, 0, 0, 1)), p.dst.address)
        assertEquals(443, p.dst.port)
        assertArrayEquals("hi".toByteArray(), p.payload)
    }

    @Test
    fun dropsFragmentedUdp() {
        val pkt = bytes(0, 0, 1, 1, 10, 0, 0, 1, 0, 53, 7)
        assertNull(Socks5Codec.parseUdp(pkt, pkt.size))
    }

    @Test
    fun udpEncodeRoundTrips() {
        val src = InetSocketAddress(InetAddress.getByAddress(bytes(1, 2, 3, 4)), 5353)
        val enc = Socks5Codec.encodeUdp(src, "abc".toByteArray(), 3)
        val p = Socks5Codec.parseUdp(enc, enc.size)!!
        assertEquals(src, p.dst)
        assertArrayEquals("abc".toByteArray(), p.payload)
    }
}
