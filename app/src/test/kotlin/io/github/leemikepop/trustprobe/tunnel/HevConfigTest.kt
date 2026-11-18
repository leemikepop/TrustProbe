package io.github.leemikepop.trustprobe.tunnel

import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class HevConfigTest {
    @Test
    fun rendersExpectedYaml() {
        val yaml = HevConfig.render(12345, Socks5Credentials("user-A_1", "pass-B_2"))
        assertEquals(
            """
            tunnel:
              mtu: 8500
              ipv4: 198.18.0.1
              ipv6: 'fc00::1'
            socks5:
              port: 12345
              address: 127.0.0.1
              udp: 'udp'
              username: 'user-A_1'
              password: 'pass-B_2'
            misc:
              log-level: warn

            """.trimIndent(),
            yaml,
        )
    }

    @Test
    fun rejectsCredentialsThatWouldBreakQuoting() {
        assertThrows(IllegalArgumentException::class.java) {
            HevConfig.render(1080, Socks5Credentials("it's", "pw"))
        }
    }
}
