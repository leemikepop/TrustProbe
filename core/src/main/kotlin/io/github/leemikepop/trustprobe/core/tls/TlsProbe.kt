package io.github.leemikepop.trustprobe.core.tls

import io.github.leemikepop.trustprobe.core.evidence.RequestEvidence
import io.github.leemikepop.trustprobe.core.evidence.RequestEvidenceParser
import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import io.github.leemikepop.trustprobe.core.probe.RejectStage
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.function.BiFunction
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLException
import javax.net.ssl.X509ExtendedKeyManager

data class ProbeTimeouts(val handshakeMs: Long = 10_000, val firstDataMs: Long = 5_000)

/**
 * Acts as the TLS server for one connection, presenting the [ProbeCase]'s untrusted certificate,
 * and reports whether the client accepted it (finished the handshake and sent data) or not.
 */
class TlsProbe(private val certs: CertificateFactory, private val timeouts: ProbeTimeouts = ProbeTimeouts()) {
    /**
     * 阻塞；initial = 已讀出的 ClientHello 位元組。回傳結果與未遮蔽的第一筆明文（只給記憶體用）。
     * Never throws; always closes [client].
     */
    fun run(client: Socket, initial: ByteArray, sni: String, case: ProbeCase): Pair<ProbeResult, ByteArray?> {
        val start = System.nanoTime()
        var engine: SSLEngine? = null
        var io: EngineIo? = null
        var tlsVersion: String? = null
        var completed = false

        fun result(kind: OutcomeKind, stage: RejectStage?, detail: String?, evidence: RequestEvidence?) =
            ProbeResult(case, kind, stage, detail, tlsVersion, evidence, (System.nanoTime() - start) / 1_000_000)

        try {
            val eng = newEngine(certs.materialFor(case, sni)).also { engine = it }
            val engineIo = EngineIo(eng, client, initial).also { io = it }
            engineIo.handshake(timeouts.handshakeMs)
            val session = eng.session
            check(session.protocol != "NONE" && session.cipherSuite != "SSL_NULL_WITH_NULL_NULL") {
                "handshake ended without a negotiated session"
            }
            completed = true
            tlsVersion = session.protocol
            val data = engineIo.firstData(timeouts.firstDataMs, MAX_FIRST_DATA)
            return result(OutcomeKind.ACCEPTED, null, null, RequestEvidenceParser.parse(data)) to data
        } catch (e: Exception) {
            // Only once the client has our certificate can a close or engine failure be its rejection.
            val clientSawCert = completed || io?.flightSent == true
            val kind = when (e) {
                is SocketTimeoutException -> OutcomeKind.TIMEOUT
                is EngineIo.PeerClosed, is SSLException -> if (clientSawCert) OutcomeKind.REJECTED else OutcomeKind.ERROR
                else -> OutcomeKind.ERROR
            }
            val stage = when {
                kind != OutcomeKind.REJECTED -> null
                completed -> RejectStage.CLOSED_AFTER_HANDSHAKE
                else -> RejectStage.ALERT_OR_CLOSE_DURING_HANDSHAKE
            }
            return result(kind, stage, e.message ?: e.javaClass.name, null) to null
        } finally {
            engine?.let { runCatching { it.closeOutbound() }; runCatching { it.closeInbound() } }
            runCatching { client.close() }
        }
    }

    private fun newEngine(material: KeyMaterial): SSLEngine {
        val context = SSLContext.getInstance("TLS")
        context.init(arrayOf(SingleKeyManager(material)), null, null)
        return context.createSSLEngine().apply {
            useClientMode = false
            // Prefer http/1.1, else agree to whatever the client wants first (an h2-only client
            // given no ALPN would close on its own and look like a rejection). "" means no
            // ALPN; null would abort the handshake.
            handshakeApplicationProtocolSelector = BiFunction { _, offered ->
                when {
                    HTTP_1_1 in offered -> HTTP_1_1
                    offered.isNotEmpty() -> offered.first()
                    else -> ""
                }
            }
        }
    }

    /** Always serves the one [KeyMaterial]; no KeyStore, so it behaves the same on the JDK and Conscrypt. */
    private class SingleKeyManager(private val material: KeyMaterial) : X509ExtendedKeyManager() {
        override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?) =
            ALIAS

        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?) = ALIAS

        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(ALIAS)

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
            if (alias == ALIAS) material.chain.toTypedArray() else null

        override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == ALIAS) material.privateKey else null

        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? =
            null
    }

    private companion object {
        const val ALIAS = "probe"
        const val HTTP_1_1 = "http/1.1"
        const val MAX_FIRST_DATA = 16 * 1024
    }
}
