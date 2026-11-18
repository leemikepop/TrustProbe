package io.github.leemikepop.trustprobe.testbed

import kotlinx.coroutines.runBlocking
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ScenariosTest {
    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        val serverCert = HeldCertificate.Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .build()
        val handshake = HandshakeCertificates.Builder().heldCertificate(serverCert).build()
        server = MockWebServer()
        server.useHttps(handshake.sslSocketFactory())
        server.enqueue(MockResponse.Builder().body("ok").build())
        server.start()
    }

    @After
    fun tearDown() {
        server.close()
    }

    private fun url() = "https://localhost:${server.port}/"

    @Test
    fun trustAllAcceptsSelfSigned() = runBlocking {
        val run = attemptRequests(clientFor(Scenario.TRUST_ALL), url(), delayMs = 0)
        assertTrue(run.success)
        assertEquals(1, run.attempts)
    }

    @Test
    fun correctRejectsSelfSigned() = runBlocking {
        val run = attemptRequests(clientFor(Scenario.CORRECT), url(), delayMs = 0)
        assertFalse(run.success)
        assertEquals(4, run.attempts)
    }

    @Test
    fun retriesThreeTimes() = runBlocking {
        val deadUrl = url()
        server.close() // nothing listens any more: every attempt fails
        val run = attemptRequests(clientFor(Scenario.TRUST_ALL), deadUrl, delayMs = 0)
        assertFalse(run.success)
        assertEquals(4, run.attempts)
    }
}
