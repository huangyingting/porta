package dev.porta.android;

import android.content.Context;
import android.content.res.Configuration;
import android.os.LocaleList;
import android.security.NetworkSecurityPolicy;
import android.test.InstrumentationTestCase;
import android.test.InstrumentationTestRunner;
import android.util.Base64;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import portamobile.CertificateVerifier;
import portamobile.Dialer;
import portamobile.Portamobile;

@SuppressWarnings("deprecation")
public final class CertificateVerificationTest extends InstrumentationTestCase {
    public void testCleartextIsRestrictedToPublicCertificateRevocationHosts() {
        NetworkSecurityPolicy policy = NetworkSecurityPolicy.getInstance();
        assertTrue(policy.isCleartextTrafficPermitted("ye2.c.lencr.org"));
        assertTrue(policy.isCleartextTrafficPermitted("c.lencr.org"));
        assertFalse(policy.isCleartextTrafficPermitted("porta.example.com"));
        assertFalse(policy.isCleartextTrafficPermitted("c.lencr.org.attacker.invalid"));
        assertFalse(policy.isCleartextTrafficPermitted("other.lencr.org"));
    }

    public void testChineseResourcesArePackaged() {
        Context context = getInstrumentation().getTargetContext();
        Configuration configuration = new Configuration(context.getResources().getConfiguration());
        configuration.setLocales(new LocaleList(Locale.SIMPLIFIED_CHINESE));
        Context chinese = context.createConfigurationContext(configuration);
        assertEquals("连接已阻止", localizedString(chinese, "connection_blocked"));
        assertEquals("断开", localizedString(chinese, "notification_disconnect"));
    }

    public void testNativeAndAndroidVerificationRejectUntrustedCertificates() throws Exception {
        byte[] chain;
        try (java.io.InputStream input = getInstrumentation().getContext().getAssets()
                .open("untrusted-certificate.pem")) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[2048];
            int read;
            while ((read = input.read(buffer)) >= 0) output.write(buffer, 0, read);
            chain = output.toByteArray();
        }
        PlatformCertificateVerifier verifier = new PlatformCertificateVerifier();
        assertFalse("Android accepted an untrusted test root",
                verifier.verify("vpn.example.com", chain, System.currentTimeMillis()).isEmpty());
        expectRejected("vpn.example.com", chain, System.currentTimeMillis(), verifier);
        AtomicBoolean consulted = new AtomicBoolean();
        CertificateVerifier accept = (host, certificates, time) -> {
            consulted.set(true);
            return "";
        };
        // Even a broken callback cannot override native identity or validity checks.
        expectRejected("wrong.example.com", chain, System.currentTimeMillis(), accept);
        assertFalse(consulted.get());
        expectRejected("vpn.example.com", chain, 946684800000L, accept);
        assertFalse(consulted.get());
        expectRejected("vpn.example.com", chain, 2524608000000L, accept);
        assertFalse(consulted.get());
    }

    public void testOptionalLiveGatewayCertificateWithoutOcspStaple() throws Exception {
        URI server = liveOrigin();
        if (server == null) return;
        int port = server.getPort() == -1 ? 443 : server.getPort();
        Certificate[] chain;
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            socket.setSoTimeout(15_000);
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            socket.connect(new InetSocketAddress(server.getHost(), port), 15_000);
            socket.startHandshake();
            chain = socket.getSession().getPeerCertificates();
        }
        PlatformCertificateVerifier verifier = new PlatformCertificateVerifier();
        Portamobile.verifyCertificateChain(server.getHost(), pem(chain), System.currentTimeMillis(), verifier);
        X509Certificate leaf = (X509Certificate) chain[0];
        expectRejected(server.getHost(), pem(chain), leaf.getNotAfter().getTime() + 1_000, verifier);
        expectRejected("wrong.example.invalid", pem(chain), System.currentTimeMillis(), verifier);
        byte[] invalidLeaf = leaf.getEncoded().clone();
        invalidLeaf[invalidLeaf.length - 1] ^= 1;
        expectRejected(server.getHost(), pem(invalidLeaf), System.currentTimeMillis(), verifier);
    }

    public void testOptionalLiveGoTransportVerifiesTlsBeforeRequestingProof() throws Exception {
        URI server = liveOrigin();
        if (server == null) return;
        InetAddress remote = InetAddress.getAllByName(server.getHost())[0];
        for (InetAddress address : InetAddress.getAllByName(server.getHost())) {
            if (address instanceof Inet4Address) {
                remote = address;
                break;
            }
        }
        AtomicBoolean proofRequested = new AtomicBoolean();
        Dialer dialer = Portamobile.newDialer();
        try {
            dialer.dialWithPlatform(server.toString(), "certificate-probe-no-account",
                    remote.getHostAddress(), fd -> "", new PlatformCertificateVerifier(),
                    (method, path) -> {
                        assertEquals("CONNECT", method);
                        assertEquals("/.well-known/masque/ip/*/*/", path);
                        proofRequested.set(true);
                        throw new Exception("intentional device proof probe rejection");
                    });
            fail("The probe must not establish an authenticated tunnel");
        } catch (Exception error) {
            assertTrue("Go TLS did not reach the proof callback: " + error, proofRequested.get());
            assertFalse(Portamobile.isTransportUnavailable(error.getMessage()));
        } finally {
            dialer.close();
        }
    }

    public void testOptionalUntrustedGoTransportNeverRequestsProof() throws Exception {
        String origin = ((InstrumentationTestRunner) getInstrumentation()).getArguments()
                .getString("portaUntrustedTlsOrigin");
        if (origin == null) return;
        URI server = new URI(origin);
        assertEquals("https", server.getScheme());
        AtomicBoolean proofRequested = new AtomicBoolean();
        Dialer dialer = Portamobile.newDialer();
        try {
            dialer.dialWithPlatform(origin, "certificate-probe-no-account",
                    InetAddress.getByName(server.getHost()).getHostAddress(), fd -> "",
                    new PlatformCertificateVerifier(), (method, path) -> {
                        proofRequested.set(true);
                        throw new Exception("unexpected device proof");
                    });
            fail("An untrusted TLS certificate must not establish a tunnel");
        } catch (Exception error) {
            assertFalse("An untrusted gateway requested a device proof", proofRequested.get());
            assertFalse(Portamobile.isTransportUnavailable(error.getMessage()));
            assertFalse(Portamobile.isRetryable(error.getMessage()));
        } finally {
            dialer.close();
        }
    }

    private URI liveOrigin() throws Exception {
        String origin = ((InstrumentationTestRunner) getInstrumentation()).getArguments()
                .getString("portaTlsOrigin");
        if (origin == null) {
            Log.i("PortaCertificateProbe", "Live TLS probe skipped: set portaTlsOrigin");
            return null;
        }
        URI server = new URI(origin);
        assertEquals("https", server.getScheme());
        assertNotNull(server.getHost());
        return server;
    }

    private String localizedString(Context context, String name) {
        int resource = context.getResources().getIdentifier(name, "string", context.getPackageName());
        assertTrue("Missing packaged string " + name, resource != 0);
        return context.getString(resource);
    }

    private void expectRejected(String host, byte[] chain, long time, CertificateVerifier verifier)
            throws Exception {
        try {
            Portamobile.verifyCertificateChain(host, chain, time, verifier);
            fail("Invalid certificate was accepted");
        } catch (Exception expected) {
            assertFalse(Portamobile.isTransportUnavailable(expected.getMessage()));
            assertFalse(Portamobile.isRetryable(expected.getMessage()));
        }
    }

    private static byte[] pem(Certificate[] chain) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (Certificate certificate : chain) output.write(pem(certificate.getEncoded()));
        return output.toByteArray();
    }

    private static byte[] pem(byte[] certificate) {
        return ("-----BEGIN CERTIFICATE-----\n" + Base64.encodeToString(certificate, Base64.NO_WRAP)
                + "\n-----END CERTIFICATE-----\n").getBytes(StandardCharsets.US_ASCII);
    }
}
