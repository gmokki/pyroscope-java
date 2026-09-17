package io.pyroscope.javaagent.api;

import io.pyroscope.javaagent.config.Config;
import io.pyroscope.javaagent.impl.PyroscopeExporter;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DynamicTlsContextTest {
    private static final String[] RSA = {"RSA"};

    @Test
    void handshakeStaysPinnedToIdentityChosenBeforeRotation() {
        FakeIdentity old = new FakeIdentity("client");
        FakeIdentity rotated = new FakeIdentity("client");
        DynamicTlsContext context = DynamicTlsContext.create(old, null);
        X509ExtendedKeyManager km = context.keyManager();

        String alias = km.chooseClientAlias(RSA, null, null);
        context.update(rotated, null);

        assertSame(old.key, km.getPrivateKey(alias));
        assertSame(old.chain, km.getCertificateChain(alias));
    }

    @Test
    void newHandshakesUseRotatedIdentity() {
        FakeIdentity old = new FakeIdentity("client");
        FakeIdentity rotated = new FakeIdentity("client");
        DynamicTlsContext context = DynamicTlsContext.create(old, null);
        X509ExtendedKeyManager km = context.keyManager();
        context.update(rotated, null);

        String alias = km.chooseClientAlias(RSA, null, null);

        assertSame(rotated.key, km.getPrivateKey(alias));
        assertSame(rotated.chain, km.getCertificateChain(alias));
    }

    @Test
    void identityPinnedLongAgoIsForgotten() {
        DynamicTlsContext context = DynamicTlsContext.create(new FakeIdentity("client"), null);
        String alias = context.keyManager().chooseClientAlias(RSA, null, null);

        for (int i = 0; i < 4; i++) {
            context.update(new FakeIdentity("client"), null);
        }

        assertNull(context.keyManager().getPrivateKey(alias));
        assertNull(context.keyManager().getCertificateChain(alias));
    }

    @Test
    void nullKeyManagerPresentsNoClientCertificate() {
        DynamicTlsContext context = DynamicTlsContext.create(null, null);
        X509ExtendedKeyManager km = context.keyManager();

        assertNull(km.chooseClientAlias(RSA, null, null));
        assertNull(km.chooseEngineClientAlias(RSA, null, null));
        assertNull(km.getClientAliases("RSA", null));
        assertNull(km.getPrivateKey("1:client"));
        assertNull(km.getCertificateChain("unknown"));
    }

    @Test
    void emptyClientAliasesAreReportedAsNone() {
        FakeIdentity noAliases = new FakeIdentity("client") {
            @Override
            public String[] getClientAliases(String keyType, Principal[] issuers) {
                return new String[0];
            }
        };
        DynamicTlsContext context = DynamicTlsContext.create(noAliases, null);

        assertNull(context.keyManager().getClientAliases("RSA", null));
    }

    @Test
    void trustManagerSwapsAndFallsBackToJvmDefault() {
        X509Certificate[] issuers = new X509Certificate[0];
        DynamicTlsContext context = DynamicTlsContext.create(null, new FakeTrustManager(issuers));

        assertSame(issuers, context.trustManager().getAcceptedIssuers());

        context.update(null, null);

        assertTrue(context.trustManager().getAcceptedIssuers().length > 0);
    }

    @Test
    void exporterBuildsWithSocketFactory() {
        DynamicTlsContext context = DynamicTlsContext.create(new FakeIdentity("client"), null);
        PyroscopeExporter exporter = new PyroscopeExporter(
            new Config.Builder()
                .setServerAddress("https://localhost:4040")
                .setApplicationName("test.app")
                .build(),
            (level, msg, args) -> {},
            context.socketFactory(),
            context.trustManager());
        exporter.stop();
    }

    /** Key manager with a single alias whose key and chain are unique to the instance. */
    private static class FakeIdentity extends X509ExtendedKeyManager {
        final String alias;
        final PrivateKey key = new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return "RSA";
            }

            @Override
            public String getFormat() {
                return null;
            }

            @Override
            public byte[] getEncoded() {
                return null;
            }
        };
        final X509Certificate[] chain = new X509Certificate[0];

        FakeIdentity(String alias) {
            this.alias = alias;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[]{alias};
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return alias;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return alias;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return this.alias.equals(alias) ? chain : null;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return this.alias.equals(alias) ? key : null;
        }
    }

    /** Trust manager that exposes a sentinel accepted-issuers array. */
    private static final class FakeTrustManager extends X509ExtendedTrustManager {
        private final X509Certificate[] acceptedIssuers;

        FakeTrustManager(X509Certificate[] acceptedIssuers) {
            this.acceptedIssuers = acceptedIssuers;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return acceptedIssuers;
        }
    }
}
