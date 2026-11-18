package io.github.leemikepop.trustprobe.testbed

import android.util.Log
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.CertificatePinner
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Ground-truth HTTPS clients. [expected] is the name of the verdict TrustProbe must reach
 * for [host]; the end-to-end test checks against it.
 */
enum class Scenario(val host: String, val expected: String) {
    /** Not insecure: default OkHttp (platform trust, default hostname verifier). */
    CORRECT("example.com", "PASS"),

    /**
     * Deliberately insecure: trust-everything [X509TrustManager] plus an always-true hostname
     * verifier, the classic copy-paste "fix" for certificate errors. Accepts any certificate
     * (T2 and T3), so the verdict is VULNERABLE.
     */
    TRUST_ALL("example.net", "VULNERABLE"),

    /**
     * Deliberately weak but not exploitable here: always-true hostname verifier with the default
     * trust manager. The chain check still rejects a forged certificate, so v1 reports PASS
     * (a wrong-hostname test, T4, is phase two).
     */
    HOSTNAME_VERIFIER_ALWAYS_TRUE("example.org", "PASS"),

    /** Not insecure: default trust plus a [CertificatePinner] on an intermediate CA. */
    PINNED("www.example.com", "PASS"),
}

data class ScenarioRun(val attempts: Int, val success: Boolean, val elapsedMs: Long)

// Pin taken 2026-11-18. SPKI SHA-256 of the intermediate CA at chain index 2, "SSL.com TLS Transit ECC CA R2" (index 1,
// the Cloudflare issuing CA, rotates more often). Regenerate with, and check the printed subject:
//   echo | openssl s_client -connect www.example.com:443 -servername www.example.com -showcerts 2>/dev/null \
//     | awk '/BEGIN CERT/{n++} n==3{print} /END CERT/&&n==3{exit}' > ca.pem
//   openssl x509 -in ca.pem -noout -subject
//   openssl x509 -in ca.pem -pubkey -noout | openssl pkey -pubin -outform der \
//     | openssl dgst -sha256 -binary | base64
private const val PIN_WWW_EXAMPLE_COM = "sha256/OXyj9ngbqO9cjLeO/+t9Ggl2EP4JTnVWHq4LEwhFM9w="

private const val MAX_ATTEMPTS = 4
private const val RETRY_DELAY_MS = 200L

private object TrustAllManager : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

fun clientFor(s: Scenario): OkHttpClient = clientFor(s, null)

/** [pinner] overrides the PINNED scenario's pinner; tests use it to pin against a local server. */
internal fun clientFor(s: Scenario, pinner: CertificatePinner?): OkHttpClient {
    val defaultTrust = platformTrustManager()
    val trust = if (s == Scenario.TRUST_ALL) TrustAllManager else defaultTrust
    // One SSLContext per client: its session cache is per client, so no resumption across attempts.
    val ctx = SSLContext.getInstance("TLS").apply { init(null, arrayOf<TrustManager>(trust), null) }
    val builder = OkHttpClient.Builder()
        .connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS)) // every attempt = fresh TCP+TLS
        .retryOnConnectionFailure(false)
        .connectTimeout(10, TimeUnit.SECONDS)
        .sslSocketFactory(ctx.socketFactory, trust)
    when (s) {
        Scenario.CORRECT -> Unit
        Scenario.TRUST_ALL -> builder.hostnameVerifier { _, _ -> true }
        Scenario.HOSTNAME_VERIFIER_ALWAYS_TRUE -> builder.hostnameVerifier { _, _ -> true }
        Scenario.PINNED -> builder.certificatePinner(
            pinner ?: CertificatePinner.Builder().add(Scenario.PINNED.host, PIN_WWW_EXAMPLE_COM).build(),
        )
    }
    return builder.build()
}

private fun platformTrustManager(): X509TrustManager {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(null as KeyStore?)
    return factory.trustManagers.filterIsInstance<X509TrustManager>().first()
}

/**
 * GETs [url] up to 4 times (1 + 3 retries). Success means any HTTP response arrived, whatever
 * its status: the TLS connection worked.
 */
internal suspend fun attemptRequests(
    client: OkHttpClient,
    url: String,
    delayMs: Long = RETRY_DELAY_MS,
): ScenarioRun = withContext(Dispatchers.IO) {
    val start = System.nanoTime()
    var attempts = 0
    var success = false
    while (attempts < MAX_ATTEMPTS && !success) {
        if (attempts > 0 && delayMs > 0) delay(delayMs)
        attempts++
        success = try {
            client.newCall(Request.Builder().url(url).build()).execute().use { true }
        } catch (e: Exception) {
            Log.d("TrustProbeTestbed", "attempt $attempts failed: ${e.javaClass.name}: ${e.message}")
            false
        }
    }
    ScenarioRun(attempts, success, (System.nanoTime() - start) / 1_000_000)
}

suspend fun runScenario(s: Scenario): ScenarioRun = attemptRequests(clientFor(s), "https://${s.host}/")
