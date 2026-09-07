import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HexFormat;

final class SignReleaseManifest {
    private SignReleaseManifest() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException(
                    "usage: SignReleaseManifest KEYSTORE MANIFEST SIGNATURE CERTIFICATE EXPECTED_SHA256");
        }
        char[] storePassword = requiredEnvironment("PORTA_ANDROID_KEYSTORE_PASSWORD");
        char[] keyPassword = requiredEnvironment("PORTA_ANDROID_KEY_PASSWORD");
        String alias = requiredEnvironmentString("PORTA_ANDROID_KEY_ALIAS");
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(Path.of(args[0]))) {
                keyStore.load(input, storePassword);
            }
            Key key = keyStore.getKey(alias, keyPassword);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new IllegalArgumentException("release signing alias has no private key");
            }
            Certificate certificate = keyStore.getCertificate(alias);
            if (certificate == null) {
                throw new IllegalArgumentException("release signing alias has no certificate");
            }
            byte[] encodedCertificate = certificate.getEncoded();
            String fingerprint = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(encodedCertificate));
            if (!MessageDigest.isEqual(
                    fingerprint.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    args[4].toLowerCase().getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                throw new IllegalArgumentException(
                        "release signing certificate does not match the pinned fingerprint");
            }

            String keyAlgorithm = key.getAlgorithm();
            String signatureAlgorithm;
            if ("EC".equalsIgnoreCase(keyAlgorithm)) {
                signatureAlgorithm = "SHA256withECDSA";
            } else if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
                signatureAlgorithm = "SHA256withRSA";
            } else {
                throw new IllegalArgumentException(
                        "unsupported release signing key algorithm: " + keyAlgorithm);
            }
            Signature signer = Signature.getInstance(signatureAlgorithm);
            signer.initSign(privateKey);
            signer.update(Files.readAllBytes(Path.of(args[1])));
            Files.write(Path.of(args[2]), signer.sign());
            Files.write(Path.of(args[3]), encodedCertificate);
        } finally {
            Arrays.fill(storePassword, '\0');
            Arrays.fill(keyPassword, '\0');
        }
    }

    private static char[] requiredEnvironment(String name) {
        return requiredEnvironmentString(name).toCharArray();
    }

    private static String requiredEnvironmentString(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
