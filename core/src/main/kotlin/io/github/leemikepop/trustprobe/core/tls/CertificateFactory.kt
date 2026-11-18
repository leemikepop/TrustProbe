package io.github.leemikepop.trustprobe.core.tls

import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.net.IDN
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

data class KeyMaterial(val privateKey: PrivateKey, val chain: List<X509Certificate>)

/**
 * Produces deliberately untrusted certificates: self-signed (T1), signed by a throwaway
 * per-instance CA (T2), and CA-signed for the wrong host (T3). Nothing is persisted.
 * Uses only the default JCA providers so it also runs on Android.
 */
class CertificateFactory(clock: () -> Instant = Instant::now) {
    private val random = SecureRandom()
    private val caKeys: KeyPair = newKeyPair()
    private val leafKeys: KeyPair = newKeyPair()
    private val cache = ConcurrentHashMap<Pair<ProbeCase, String>, KeyMaterial>()
    private val caName: X500Name = nameOf("TrustProbe Untrusted Test CA")

    // One validity window for the CA and every leaf, so leaves never outlive the CA.
    private val notBefore: Date
    private val notAfter: Date

    init {
        val now = clock()
        notBefore = Date.from(now.minusSeconds(DAY))
        notAfter = Date.from(now.plusSeconds(30 * DAY))
    }

    val sessionCa: X509Certificate = buildCa()

    /** @throws IllegalArgumentException if [sni] is blank after normalisation. */
    fun materialFor(case: ProbeCase, sni: String): KeyMaterial {
        val host = normalizeHost(sni)
        return cache.computeIfAbsent(case to host) { build(case, host) }
    }

    private fun build(case: ProbeCase, host: String): KeyMaterial = when (case) {
        ProbeCase.T1_SELF_SIGNED ->
            KeyMaterial(leafKeys.private, listOf(leaf(host, selfSigned = true)))
        ProbeCase.T2_UNTRUSTED_CA ->
            KeyMaterial(leafKeys.private, listOf(leaf(host, selfSigned = false), sessionCa))
        ProbeCase.T3_WRONG_HOST ->
            KeyMaterial(leafKeys.private, listOf(leaf(WRONG_HOST, selfSigned = false), sessionCa))
    }

    private fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"), random)
        }.generateKeyPair()

    private fun serial(): BigInteger = BigInteger(64, random).setBit(63)

    private fun buildCa(): X509Certificate {
        val builder = JcaX509v3CertificateBuilder(
            caName, serial(), notBefore, notAfter, caName, caKeys.public,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(
            Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign),
        )
        return sign(builder, caKeys.private)
    }

    private fun leaf(host: String, selfSigned: Boolean): X509Certificate {
        val subject = nameOf(host)
        val issuer = if (selfSigned) subject else caName
        val builder = JcaX509v3CertificateBuilder(
            issuer, serial(), notBefore, notAfter, subject, leafKeys.public,
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
        builder.addExtension(
            Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
        )
        val type = if (isIpLiteral(host)) GeneralName.iPAddress else GeneralName.dNSName
        builder.addExtension(
            Extension.subjectAlternativeName, false, GeneralNames(GeneralName(type, host)),
        )
        return sign(builder, if (selfSigned) leafKeys.private else caKeys.private)
    }

    private fun sign(builder: JcaX509v3CertificateBuilder, key: PrivateKey): X509Certificate =
        JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(key)),
        )

    private fun nameOf(cn: String): X500Name =
        X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, cn).build()

    companion object {
        const val WRONG_HOST = "wrong.trustprobe.invalid"
        private const val DAY = 86_400L
        private val IPV4 = Regex("""(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}""")

        /** Trim, lowercase, drop one trailing dot and brackets, punycode non-ASCII. No DNS lookups. */
        internal fun normalizeHost(sni: String): String {
            var host = sni.trim()
            if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length - 1)
            host = host.lowercase(Locale.ROOT).removeSuffix(".")
            require(host.isNotBlank()) { "blank SNI" }
            if (!isIpLiteral(host) && host.any { it.code > 127 }) {
                host = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED)
            }
            return host
        }

        internal fun isIpLiteral(host: String): Boolean = ':' in host || IPV4.matches(host)
    }
}
