package io.github.leemikepop.trustprobe.tunnel

import java.net.Inet6Address
import java.net.InetAddress

/**
 * Whether the VPN should carry IPv6. Only when the underlying network really has IPv6 (a default
 * route and a global address); otherwise the VPN stays IPv4-only, Android blocks IPv6 for the app
 * under test and the resolver stops returning AAAA, so no connection stalls on a dead IPv6 path.
 */
object Ipv6Policy {
    fun routeIpv6(hasIpv6DefaultRoute: Boolean, addresses: List<InetAddress>): Boolean =
        hasIpv6DefaultRoute && addresses.any(::isGlobalIpv6)

    private fun isGlobalIpv6(a: InetAddress): Boolean {
        if (a !is Inet6Address) return false
        if (a.isLinkLocalAddress || a.isSiteLocalAddress) return false // fe80::/10, fec0::/10
        if (a.isLoopbackAddress || a.isAnyLocalAddress || a.isMulticastAddress) return false
        return a.address[0].toInt() and 0xFE != 0xFC // not ULA fc00::/7
    }
}
