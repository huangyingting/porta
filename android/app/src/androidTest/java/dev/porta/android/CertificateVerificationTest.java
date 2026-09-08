package dev.porta.android;

import android.content.Context;
import android.security.NetworkSecurityPolicy;
import android.test.InstrumentationTestCase;
import android.test.InstrumentationTestRunner;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import portamobile.ProofProvider;
import portamobile.Protector;

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

    public void testLiveGatewayCertificateIsAcceptedWithoutAnOcspStaple() throws Exception {
        URI server = liveOrigin();
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
        byte[][] certificates = new byte[chain.length][];
        for (int index = 0; index < chain.length; index++) {
            certificates[index] = chain[index].getEncoded();
        }
        Verification result = verify(server.getHost(), certificates, System.currentTimeMillis());
        assertEquals("Android platform verification failed: " + result.message, 0, result.code);

        X509Certificate leaf = (X509Certificate) chain[0];
        Verification expired = verify(server.getHost(), certificates, leaf.getNotAfter().getTime() + 1_000);
        assertEquals("Expired certificates must still be rejected", 2, expired.code);
        certificates[0] = certificates[0].clone();
        certificates[0][certificates[0].length - 1] ^= 1;
        assertFalse("Invalid certificate signatures must still be rejected",
                verify(server.getHost(), certificates, System.currentTimeMillis()).code == 0);
    }

    public void testLiveRustTransportCompletesTlsBeforeRequestingDeviceProof() throws Exception {
        URI server = liveOrigin();
        Context context = getInstrumentation().getTargetContext();
        Class<?> bridge = Class.forName("portamobile.Portamobile", true, context.getClassLoader());
        assertEquals(Boolean.TRUE, method(bridge, "nativeInitialize", Context.class).invoke(null, context));
        InetAddress[] addresses = InetAddress.getAllByName(server.getHost());
        InetAddress remote = addresses[0];
        for (InetAddress address : addresses) {
            if (address instanceof Inet4Address) {
                remote = address;
                break;
            }
        }
        AtomicBoolean proofRequested = new AtomicBoolean();
        ProofProvider proof = (requestMethod, path) -> {
            assertEquals("CONNECT", requestMethod);
            proofRequested.set(true);
            return "{}";
        };
        Protector protector = descriptor -> "";
        long dialer = (Long) method(bridge, "nativeNewDialer").invoke(null);
        try {
            Method dial = method(bridge, "nativeDial", long.class, String.class, String.class,
                    String.class, ProofProvider.class, Protector.class);
            try {
                dial.invoke(null, dialer, server.toString(), "certificate-probe-no-account",
                        remote.getHostAddress(), proof, protector);
                fail("An intentionally invalid proof must not establish a tunnel");
            } catch (InvocationTargetException error) {
                assertTrue("Rust TLS did not reach the proof callback: " + error.getCause(),
                        proofRequested.get());
            }
        } finally {
            method(bridge, "nativeCloseDialer", long.class).invoke(null, dialer);
        }
        assertTrue(proofRequested.get());
    }

    private URI liveOrigin() throws Exception {
        String origin = ((InstrumentationTestRunner) getInstrumentation())
                .getArguments().getString("portaTlsOrigin");
        assertNotNull("Set portaTlsOrigin to run live certificate probes", origin);
        URI server = new URI(origin);
        assertEquals("https", server.getScheme());
        assertNotNull(server.getHost());
        return server;
    }

    private Verification verify(String host, byte[][] certificates, long time) throws Exception {
        Context context = getInstrumentation().getTargetContext();
        Class<?> verifier = Class.forName("org.rustls.platformverifier.CertificateVerifier",
                true, context.getClassLoader());
        Object result = method(verifier, "verifyCertificateChain", Context.class, String.class,
                String.class, String[].class, byte[].class, long.class, byte[][].class)
                .invoke(null, context, host, "RSA", new String[]{"1.3.6.1.5.5.7.3.1"},
                        null, time, certificates);
        Field code = result.getClass().getDeclaredField("code");
        code.setAccessible(true);
        Field message = result.getClass().getDeclaredField("message");
        message.setAccessible(true);
        return new Verification(code.getInt(result), (String) message.get(result));
    }

    private static Method method(Class<?> owner, String name, Class<?>... arguments) throws Exception {
        Method method = owner.getDeclaredMethod(name, arguments);
        method.setAccessible(true);
        return method;
    }

    private static final class Verification {
        final int code;
        final String message;

        Verification(int code, String message) {
            this.code = code;
            this.message = message;
        }
    }
}
