package io.github.leemikepop.trustprobe.testbed

import kotlinx.coroutines.runBlocking
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.CertificatePinner
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScenariosTest {
    private val servers = mutableListOf<MockWebServer>()

    @After
    fun tearDown() {
        servers.forEach { it.close() }
    }

    /** Starts an HTTPS server presenting [cert] (chain [extra] appended), answering [responses] 200s. */
    private fun start(cert: HeldCertificate, vararg extra: HeldCertificate, responses: Int = 1,
                      closeAfterResponse: Boolean = false): MockWebServer {
        val handshake = HandshakeCertificates.Builder().heldCertificate(cert, *extra.map { it.certificate }.toTypedArray()).build()
        val server = MockWebServer()
        server.useHttps(handshake.sslSocketFactory())
        repeat(responses) {
            val r = MockResponse.Builder().body("ok")
            if (closeAfterResponse) r.addHeader("Connection", "close")
            server.enqueue(r.build())
        }
        server.start()
        servers += server
        return server
    }

    private fun selfSigned() = HeldCertificate.Builder().commonName("localhost")
        .addSubjectAlternativeName("localhost").build()

    private fun untrustedCa() = HeldCertificate.Builder().commonName("Untrusted CA")
        .certificateAuthority(0).build()

    private fun signedBy(ca: HeldCertificate, san: String) = HeldCertificate.Builder()
        .commonName(san).addSubjectAlternativeName(san).signedBy(ca).build()

    private fun url(s: MockWebServer) = "https://localhost:${s.port}/"

    private fun run(scenario: Scenario, s: MockWebServer, pinner: CertificatePinner? = null) = runBlocking {
        attemptRequests(clientFor(scenario, pinner), url(s), delayMs = 0)
    }

    @Test
    fun trustAllAcceptsSelfSigned() {
        val r = run(Scenario.TRUST_ALL, start(selfSigned()))
        assertTrue(r.success)
        assertEquals(1, r.attempts)
    }

    @Test
    fun trustAllAcceptsWrongHostChain() {
        val ca = untrustedCa()
        val server = start(signedBy(ca, "wrong.trustprobe.invalid"), ca)
        assertTrue(run(Scenario.TRUST_ALL, server).success)
    }

    @Test
    fun correctRejectsSelfSigned() {
        val r = run(Scenario.CORRECT, start(selfSigned()))
        assertFalse(r.success)
        assertEquals(4, r.attempts)
    }

    @Test
    fun correctRejectsUntrustedCaChain() {
        val ca = untrustedCa()
        assertFalse(run(Scenario.CORRECT, start(signedBy(ca, "localhost"), ca)).success)
    }

    @Test
    fun hostnameVerifierAlwaysTrueStillRejectsUntrustedChain() {
        val ca = untrustedCa()
        val server = start(signedBy(ca, "localhost"), ca)
        assertFalse(run(Scenario.HOSTNAME_VERIFIER_ALWAYS_TRUE, server).success)
    }

    @Test
    fun pinnedRejectsUntrustedChain() {
        val ca = untrustedCa()
        val server = start(signedBy(ca, "localhost"), ca)
        val pinner = CertificatePinner.Builder()
            .add("localhost", CertificatePinner.pin(ca.certificate)).build()
        assertFalse(run(Scenario.PINNED, server, pinner).success)
    }

    @Test
    fun retriesThreeTimes() {
        val server = start(selfSigned())
        val deadUrl = url(server)
        server.close() // nothing listens any more: every attempt fails
        val r = runBlocking { attemptRequests(clientFor(Scenario.TRUST_ALL), deadUrl, delayMs = 0) }
        assertFalse(r.success)
        assertEquals(4, r.attempts)
    }

    @Test
    fun everyAttemptOpensANewConnection() {
        val server = start(selfSigned(), responses = 2, closeAfterResponse = true)
        val client = clientFor(Scenario.TRUST_ALL)
        runBlocking {
            assertTrue(attemptRequests(client, url(server), delayMs = 0).success)
            assertTrue(attemptRequests(client, url(server), delayMs = 0).success)
        }
        val first = server.takeRequest()
        val second = server.takeRequest()
        assertNotEquals(first.connectionIndex, second.connectionIndex)
    }
}
