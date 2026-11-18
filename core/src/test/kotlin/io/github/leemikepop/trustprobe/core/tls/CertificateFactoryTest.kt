package io.github.leemikepop.trustprobe.core.tls

import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.KeyStore
import java.security.cert.CertPathBuilderException
import java.security.cert.CertPathValidatorException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Instant
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CertificateFactoryTest {
    private val sni = "api.example.com"

    private fun dnsNames(cert: X509Certificate): List<String> =
        cert.subjectAlternativeNames.orEmpty().filter { it[0] == 2 }.map { it[1] as String }

    @Test
    fun t1IsSelfSignedForSni() {
        val m = CertificateFactory().materialFor(ProbeCase.T1_SELF_SIGNED, sni)
        assertEquals(1, m.chain.size)
        val leaf = m.chain[0]
        assertEquals(leaf.issuerX500Principal, leaf.subjectX500Principal)
        assertTrue(dnsNames(leaf).contains(sni))
        leaf.verify(leaf.publicKey)
    }

    @Test
    fun t2ChainsToSessionCa() {
        val f = CertificateFactory()
        val m = f.materialFor(ProbeCase.T2_UNTRUSTED_CA, sni)
        assertEquals(listOf(m.chain[0], f.sessionCa), m.chain)
        assertEquals(listOf(sni), dnsNames(m.chain[0]))
        m.chain[0].verify(f.sessionCa.publicKey)
        assertEquals(f.sessionCa.subjectX500Principal, m.chain[0].issuerX500Principal)
        assertTrue(f.sessionCa.basicConstraints >= 0)
        assertEquals("CN=TrustProbe Untrusted Test CA", f.sessionCa.subjectX500Principal.name)
    }

    @Test
    fun t3HasWrongHost() {
        val f = CertificateFactory()
        val leaf = f.materialFor(ProbeCase.T3_WRONG_HOST, sni).chain[0]
        assertEquals(listOf(CertificateFactory.WRONG_HOST), dnsNames(leaf))
        leaf.verify(f.sessionCa.publicKey)
    }


    @Test
    fun materialIsCached() {
        val f = CertificateFactory()
        assertSame(
            f.materialFor(ProbeCase.T2_UNTRUSTED_CA, sni),
            f.materialFor(ProbeCase.T2_UNTRUSTED_CA, sni),
        )
    }

    @Test
    fun validityUsesInjectedClock() {
        val now = Instant.parse("2026-01-10T12:00:00Z")
        val f = CertificateFactory { now }
        val leaf = f.materialFor(ProbeCase.T1_SELF_SIGNED, sni).chain[0]
        assertEquals(now.minusSeconds(86_400).toEpochMilli(), leaf.notBefore.time)
        assertEquals(now.plusSeconds(30 * 86_400L).toEpochMilli(), leaf.notAfter.time)
        assertEquals(now.minusSeconds(86_400).toEpochMilli(), f.sessionCa.notBefore.time)
    }

    @Test
    fun serialsAreUniqueAndLeafKeyIsReused() {
        val f = CertificateFactory()
        val a = f.materialFor(ProbeCase.T1_SELF_SIGNED, "a.example.com")
        val b = f.materialFor(ProbeCase.T2_UNTRUSTED_CA, "b.example.com")
        assertNotEquals(a.chain[0].serialNumber, b.chain[0].serialNumber)
        assertTrue(a.chain[0].serialNumber.signum() > 0)
        assertEquals(a.privateKey, b.privateKey)
        assertFalse(a.chain[0].basicConstraints >= 0)
    }

    private fun trustManagerFor(vararg anchors: X509Certificate): X509TrustManager {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
        anchors.forEachIndexed { i, c -> ks.setCertificateEntry("a$i", c) }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(ks)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    private fun causes(t: Throwable): Sequence<Throwable> = generateSequence(t) { it.cause }

    @Test
    fun allAreUntrustedByDefaultTrustManager() {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
        val f = CertificateFactory()
        for (case in ProbeCase.entries) {
            val chain = f.materialFor(case, sni).chain.toTypedArray()
            val e = assertThrows(CertificateException::class.java) {
                tm.checkServerTrusted(chain, "ECDHE_ECDSA")
            }
            assertTrue(
                "$case: $e",
                causes(e).any { it is CertPathBuilderException || it is CertPathValidatorException },
            )
        }
    }

    @Test
    fun t2AndT3AcceptedWhenSessionCaTrusted() {
        val f = CertificateFactory()
        val tm = trustManagerFor(f.sessionCa)
        for (case in listOf(ProbeCase.T2_UNTRUSTED_CA, ProbeCase.T3_WRONG_HOST)) {
            tm.checkServerTrusted(f.materialFor(case, sni).chain.toTypedArray(), "ECDHE_ECDSA")
        }
    }

    @Test
    fun t1AcceptedWhenItselfTrusted() {
        val chain = CertificateFactory().materialFor(ProbeCase.T1_SELF_SIGNED, sni).chain
        trustManagerFor(chain[0]).checkServerTrusted(chain.toTypedArray(), "ECDHE_ECDSA")
    }

    /** Local TLS handshake with HTTPS hostname verification; returns the client-side failure or null. */
    private fun handshake(f: CertificateFactory, case: ProbeCase): SSLException? {
        val material = f.materialFor(case, sni)
        val serverKs = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("k", material.privateKey, CharArray(0), material.chain.toTypedArray())
        }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(serverKs, CharArray(0))
        val serverCtx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        val clientCtx = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManagerFor(f.sessionCa)), null)
        }
        val pool = Executors.newSingleThreadExecutor()
        (serverCtx.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress())
            as SSLServerSocket).use { server ->
            server.soTimeout = 10_000
            pool.submit {
                try {
                    (server.accept() as SSLSocket).use { it.startHandshake() }
                } catch (_: Exception) {
                    // the client may abort the handshake; that is the T3 case
                }
            }
            // Named address (no DNS lookup) so SNI and the HTTPS identity check use the host.
            val addr = InetAddress.getByAddress(sni, InetAddress.getLoopbackAddress().address)
            val client = clientCtx.socketFactory.createSocket() as SSLSocket
            try {
                client.use {
                    it.soTimeout = 10_000
                    it.sslParameters = it.sslParameters.apply {
                        endpointIdentificationAlgorithm = "HTTPS"
                        serverNames = listOf(SNIHostName(sni))
                    }
                    it.connect(InetSocketAddress(addr, server.localPort), 10_000)
                    it.startHandshake()
                }
                return null
            } catch (e: SSLException) {
                return e
            } finally {
                pool.shutdown()
                pool.awaitTermination(10, TimeUnit.SECONDS)
            }
        }
    }

    @Test
    fun hostnameMatchesOnlyForT2() {
        val f = CertificateFactory()
        assertEquals(null, handshake(f, ProbeCase.T2_UNTRUSTED_CA))
        val e = handshake(f, ProbeCase.T3_WRONG_HOST)
        assertTrue("expected hostname failure, got $e", e != null)
        assertTrue(
            causes(e!!).any { it.message.orEmpty().contains("No subject alternative") },
        )
    }

    @Test
    fun ipLiteralGetsIpAddressSan() {
        val f = CertificateFactory()
        val v4 = f.materialFor(ProbeCase.T2_UNTRUSTED_CA, "192.0.2.7").chain[0]
        assertEquals(listOf(listOf(7, "192.0.2.7")), v4.subjectAlternativeNames.map { it.toList() })
        val v6 = f.materialFor(ProbeCase.T1_SELF_SIGNED, "[2001:db8::1]").chain[0]
        assertEquals(7, v6.subjectAlternativeNames.single()[0])
    }

    @Test
    fun uppercaseAndTrailingDotShareCacheEntry() {
        val f = CertificateFactory()
        assertSame(
            f.materialFor(ProbeCase.T2_UNTRUSTED_CA, "API.Example.com."),
            f.materialFor(ProbeCase.T2_UNTRUSTED_CA, "api.example.com"),
        )
    }

    @Test
    fun commaInHostDoesNotThrow() {
        val leaf = CertificateFactory().materialFor(ProbeCase.T1_SELF_SIGNED, "a,b=c.example.com").chain[0]
        assertEquals(listOf("a,b=c.example.com"), dnsNames(leaf))
    }

    @Test
    fun idnHostIsPunycoded() {
        val leaf = CertificateFactory().materialFor(ProbeCase.T2_UNTRUSTED_CA, "Bücher.example").chain[0]
        assertEquals(listOf("xn--bcher-kva.example"), dnsNames(leaf))
    }

    @Test
    fun blankSniThrows() {
        val f = CertificateFactory()
        assertThrows(IllegalArgumentException::class.java) {
            f.materialFor(ProbeCase.T1_SELF_SIGNED, "  .")
        }
    }

    @Test
    fun concurrentCallsShareOneEntry() {
        val f = CertificateFactory()
        val pool = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        val futures = (1..8).map {
            pool.submit<KeyMaterial> {
                start.await()
                f.materialFor(ProbeCase.T2_UNTRUSTED_CA, sni)
            }
        }
        start.countDown()
        val results = futures.map { it.get(30, TimeUnit.SECONDS) }
        pool.shutdown()
        results.forEach { assertSame(results[0], it) }
    }
}
