package dev.porta.android

import android.net.http.X509TrustManagerExtensions
import androidx.annotation.Keep
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import portamobile.CertificateVerifier

@Keep
class PlatformCertificateVerifier : CertificateVerifier {
    private val trustManager = X509TrustManagerExtensions(
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(null as KeyStore?)
        }.trustManagers.filterIsInstance<X509TrustManager>().single(),
    )

    override fun verify(hostname: String, chainPEM: ByteArray, unixTimeMillis: Long): String = try {
        require(hostname.isNotBlank()) { "Missing TLS hostname" }
        val certificates = CertificateFactory.getInstance("X.509")
            .generateCertificates(ByteArrayInputStream(chainPEM))
            .map { it as X509Certificate }
            .toTypedArray()
        require(certificates.isNotEmpty()) { "Missing TLS certificate chain" }
        certificates.forEach { it.checkValidity(Date(unixTimeMillis)) }
        val leaf = certificates[0]
        require(leaf.keyUsage?.firstOrNull() != false) { "Certificate cannot sign TLS handshakes" }
        require(leaf.extendedKeyUsage?.any { it == SERVER_AUTH || it == ANY_USAGE } != false) {
            "Certificate is not valid for server authentication"
        }
        val authType = when (leaf.publicKey.algorithm) {
            "RSA" -> "ECDHE_RSA"
            "EC" -> "ECDHE_ECDSA"
            else -> leaf.publicKey.algorithm
        }
        // The hostname selects Android's domain trust/pinning policy. Go separately
        // checks the SANs against the original URL, never the resolved IP address.
        trustManager.checkServerTrusted(certificates, authType, hostname)
        ""
    } catch (error: Exception) {
        error.message ?: "Android rejected the gateway certificate"
    }

    companion object {
        private const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
        private const val ANY_USAGE = "2.5.29.37.0"
    }
}
