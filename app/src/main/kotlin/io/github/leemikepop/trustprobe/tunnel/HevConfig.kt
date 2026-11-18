package io.github.leemikepop.trustprobe.tunnel

import io.github.leemikepop.trustprobe.core.socks.Socks5Credentials

/** Renders the hev-socks5-tunnel YAML that points the tun at the probe engine's SOCKS5 server. */
object HevConfig {
    const val MTU = 8500
    const val IPV4 = "198.18.0.1"
    const val IPV6 = "fc00::1"

    private val SAFE = Regex("[A-Za-z0-9_-]+")

    fun render(socksPort: Int, credentials: Socks5Credentials): String {
        // Values are single-quoted YAML scalars; the engine's random tokens are URL-safe base64.
        require(credentials.username.matches(SAFE) && credentials.password.matches(SAFE)) {
            "SOCKS5 credentials must be URL-safe base64"
        }
        return """
            |tunnel:
            |  mtu: $MTU
            |  ipv4: $IPV4
            |  ipv6: '$IPV6'
            |socks5:
            |  port: $socksPort
            |  address: 127.0.0.1
            |  udp: 'udp'
            |  username: '${credentials.username}'
            |  password: '${credentials.password}'
            |misc:
            |  log-level: warn
            |
        """.trimMargin()
    }
}
