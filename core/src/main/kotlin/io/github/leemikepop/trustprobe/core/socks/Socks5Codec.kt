package io.github.leemikepop.trustprobe.core.socks

import java.io.DataInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress

/** RFC 1928 wire format: only what the server needs (no-auth, CONNECT, UDP ASSOCIATE). */
object Socks5Codec {
    const val VERSION = 5
    const val CMD_CONNECT = 0x01
    const val CMD_UDP_ASSOCIATE = 0x03
    const val REP_OK = 0x00
    const val REP_COMMAND_NOT_SUPPORTED = 0x07
    const val REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

    private const val ATYP_IPV4 = 0x01
    private const val ATYP_DOMAIN = 0x03
    private const val ATYP_IPV6 = 0x04

    class Request(val cmd: Int, val dst: InetSocketAddress)
    class UdpPacket(val dst: InetSocketAddress, val payload: ByteArray)

    /** Thrown for a request whose address type is unknown; carries the reply code to send. */
    class UnsupportedAddressType : java.io.IOException("unsupported address type")

    /** Reads the method-selection message; returns true if "no authentication" (0x00) is offered. */
    fun readGreeting(input: InputStream): Boolean {
        val d = DataInputStream(input)
        require(d.readUnsignedByte() == VERSION) { "not SOCKS5" }
        val methods = ByteArray(d.readUnsignedByte())
        d.readFully(methods)
        return methods.any { it.toInt() == 0 }
    }

    fun readRequest(input: InputStream): Request {
        val d = DataInputStream(input)
        require(d.readUnsignedByte() == VERSION) { "not SOCKS5" }
        val cmd = d.readUnsignedByte()
        d.readUnsignedByte() // RSV
        val host: ByteArray
        val domain: String?
        when (d.readUnsignedByte()) {
            ATYP_IPV4 -> { host = ByteArray(4).also(d::readFully); domain = null }
            ATYP_IPV6 -> { host = ByteArray(16).also(d::readFully); domain = null }
            ATYP_DOMAIN -> {
                val raw = ByteArray(d.readUnsignedByte()).also(d::readFully)
                host = raw
                domain = String(raw, Charsets.US_ASCII)
            }
            else -> throw UnsupportedAddressType()
        }
        val port = d.readUnsignedShort()
        val dst = if (domain != null) InetSocketAddress(domain, port)
        else InetSocketAddress(InetAddress.getByAddress(host), port)
        return Request(cmd, dst)
    }

    /** Builds a reply; BND defaults to 0.0.0.0:0. */
    fun reply(rep: Int, bind: InetSocketAddress? = null): ByteArray {
        val addr = bind?.address?.address ?: ByteArray(4)
        val port = bind?.port ?: 0
        val atyp = if (addr.size == 16) ATYP_IPV6 else ATYP_IPV4
        return byteArrayOf(VERSION.toByte(), rep.toByte(), 0, atyp.toByte()) + addr +
            byteArrayOf((port shr 8).toByte(), port.toByte())
    }

    /** Parses a UDP datagram; returns null if malformed or fragmented (FRAG != 0). */
    fun parseUdp(data: ByteArray, length: Int): UdpPacket? {
        if (length < 4 || data[0].toInt() != 0 || data[1].toInt() != 0 || data[2].toInt() != 0) return null
        var off = 4
        val dst = when (data[3].toInt()) {
            ATYP_IPV4 -> {
                if (length < off + 4 + 2) return null
                InetAddress.getByAddress(data.copyOfRange(off, off + 4)).also { off += 4 }
            }
            ATYP_IPV6 -> {
                if (length < off + 16 + 2) return null
                InetAddress.getByAddress(data.copyOfRange(off, off + 16)).also { off += 16 }
            }
            ATYP_DOMAIN -> {
                if (length < off + 1) return null
                val n = data[off].toInt() and 0xFF
                if (length < off + 1 + n + 2) return null
                val name = String(data, off + 1, n, Charsets.US_ASCII)
                off += 1 + n
                runCatching { InetAddress.getByName(name) }.getOrNull() ?: return null
            }
            else -> return null
        }
        val port = ((data[off].toInt() and 0xFF) shl 8) or (data[off + 1].toInt() and 0xFF)
        off += 2
        return UdpPacket(InetSocketAddress(dst, port), data.copyOfRange(off, length))
    }

    /** Wraps [payload] (first [length] bytes) with a UDP header naming [peer]. */
    fun encodeUdp(peer: InetSocketAddress, payload: ByteArray, length: Int): ByteArray {
        val addr = peer.address.address
        val atyp = if (addr.size == 16) ATYP_IPV6 else ATYP_IPV4
        val header = byteArrayOf(0, 0, 0, atyp.toByte()) + addr +
            byteArrayOf((peer.port shr 8).toByte(), peer.port.toByte())
        return header + payload.copyOfRange(0, length)
    }
}
