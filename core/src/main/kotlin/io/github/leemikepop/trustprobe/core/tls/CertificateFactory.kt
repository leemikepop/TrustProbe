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
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import org.bouncycastle.asn1.x500.X500Name
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
class CertificateFactory(private val clock: () -> Instant = Instant::now) {
    private val random = SecureRandom()
    private val caKeys: KeyPair = newKeyPair()
    private val leafKeys: KeyPair = newKeyPair()
    private val cache = ConcurrentHashMap<Pair<ProbeCase, String>, KeyMaterial>()

    val sessionCa: X509Certificate = buildCa()

    fun materialFor(case: ProbeCase, sni: String): KeyMaterial =
        cache.computeIfAbsent(case to sni) { build(case, sni) }

    private fun build(case: ProbeCase, sni: String): KeyMaterial = when (case) {
        ProbeCase.T1_SELF_SIGNED ->
            KeyMaterial(leafKeys.private, listOf(leaf(sni, leafKeys.private)))
        ProbeCase.T2_UNTRUSTED_CA ->
            KeyMaterial(leafKeys.private, listOf(leaf(sni, caKeys.private), sessionCa))
        ProbeCase.T3_WRONG_HOST ->
            KeyMaterial(leafKeys.private, listOf(leaf(WRONG_HOST, caKeys.private), sessionCa))
    }

    private fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"), random)
        }.generateKeyPair()

    private fun serial(): BigInteger = BigInteger(64, random).setBit(63)

    private fun window(): Pair<Date, Date> {
        val now = clock()
        return Date.from(now.minusSeconds(DAY)) to Date.from(now.plusSeconds(30 * DAY))
    }

    private fun buildCa(): X509Certificate {
        val name = X500Name("CN=TrustProbe Untrusted Test CA")
        val (from, to) = window()
        val builder = JcaX509v3CertificateBuilder(name, serial(), from, to, name, caKeys.public)
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(
            Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign),
        )
        return sign(builder, caKeys.private)
    }

    /** Builds a leaf for [host]; issuer is the CA name unless signed by the leaf key itself. */
    private fun leaf(host: String, signer: PrivateKey): X509Certificate {
        val subject = X500Name("CN=$host")
        val selfSigned = signer == leafKeys.private
        val issuer = if (selfSigned) subject else X500Name("CN=TrustProbe Untrusted Test CA")
        val (from, to) = window()
        val builder = JcaX509v3CertificateBuilder(issuer, serial(), from, to, subject, leafKeys.public)
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
        builder.addExtension(
            Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
        )
        builder.addExtension(
            Extension.subjectAlternativeName, false,
            GeneralNames(GeneralName(GeneralName.dNSName, host)),
        )
        return sign(builder, signer)
    }

    private fun sign(builder: JcaX509v3CertificateBuilder, key: PrivateKey): X509Certificate =
        JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(key)),
        )

    companion object {
        const val WRONG_HOST = "wrong.trustprobe.invalid"
        private const val DAY = 86_400L
    }
}
