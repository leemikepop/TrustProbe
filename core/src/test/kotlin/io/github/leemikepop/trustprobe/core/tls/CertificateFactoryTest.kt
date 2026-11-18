package io.github.leemikepop.trustprobe.core.tls

import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Instant
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
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
    fun allAreUntrustedByDefaultTrustManager() {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
        val f = CertificateFactory()
        for (case in ProbeCase.entries) {
            val chain = f.materialFor(case, sni).chain.toTypedArray()
            try {
                tm.checkServerTrusted(chain, "ECDSA")
                fail("$case should be untrusted")
            } catch (_: CertificateException) {
            }
        }
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
}
