package io.github.leemikepop.trustprobe.tunnel

import java.net.InetAddress
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Ipv6PolicyTest {
    private fun addrs(vararg s: String) = s.map(InetAddress::getByName)

    @Test
    fun ipv4OnlyNetworkGetsNoIpv6() {
        assertFalse(Ipv6Policy.routeIpv6(hasIpv6DefaultRoute = false, addresses = addrs("10.0.2.15")))
    }

    @Test
    fun emulatorSiteLocalOnlyGetsNoIpv6() {
        // The emulator's SLIRP network: fec0::/10 plus link-local, no IPv6 default route.
        val a = addrs("10.0.2.15", "fec0::5054:ff:fe12:3456", "fe80::5054:ff:fe12:3456")
        assertFalse(Ipv6Policy.routeIpv6(hasIpv6DefaultRoute = false, addresses = a))
        assertFalse(Ipv6Policy.routeIpv6(hasIpv6DefaultRoute = true, addresses = a))
    }

    @Test
    fun uniqueLocalOnlyGetsNoIpv6() {
        assertFalse(Ipv6Policy.routeIpv6(hasIpv6DefaultRoute = true, addresses = addrs("fd12:3456::1", "fc00::2")))
    }

    @Test
    fun globalIpv6WithDefaultRouteGetsIpv6() {
        assertTrue(
            Ipv6Policy.routeIpv6(
                hasIpv6DefaultRoute = true,
                addresses = addrs("192.168.1.20", "fe80::1", "2001:db8:1234::20"),
            ),
        )
    }

    @Test
    fun globalIpv6WithoutDefaultRouteGetsNoIpv6() {
        assertFalse(Ipv6Policy.routeIpv6(hasIpv6DefaultRoute = false, addresses = addrs("2001:db8:1234::20")))
    }
}
