package io.pyroscope.javaagent.api;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * An {@link SSLContext} whose client identity and server trust can be replaced at runtime.
 * <p>
 * Wire {@link #socketFactory()} and {@link #trustManager()} into
 * {@code PyroscopeAgent.Options.Builder#setSslSocketFactory}, then call {@link #update} from the
 * application's certificate rotation callback. Handshakes that start after {@code update} returns
 * use the new material. Each handshake is pinned to the material it started with, so a rotation
 * during a handshake cannot pair the key of one identity with the certificate of another. Cached
 * TLS sessions are invalidated on {@code update}, so new connections cannot resume a session that
 * was authenticated with the previous identity. Connections that are already open keep the
 * identity they were established with until they are closed.
 * <p>
 * A {@code null} key manager presents no client certificate. A {@code null} trust manager uses
 * the JVM default trust store.
 */
public final class DynamicTlsContext {

    private static final String PIN_SEPARATOR = ":";
    /** How many superseded generations stay resolvable for handshakes that started before an update. */
    private static final int RETAINED_GENERATIONS = 4;

    private final SSLContext sslContext;
    private final PinningKeyManager keyManager = new PinningKeyManager();
    private final SwappableTrustManager trustManager = new SwappableTrustManager();
    private final X509ExtendedTrustManager defaultTrustManager = systemDefaultTrustManager();
    private final AtomicReference<Material> current = new AtomicReference<>(new Material(0, null, null));
    private final ConcurrentMap<Long, Material> retained = new ConcurrentHashMap<>();

    private DynamicTlsContext() {
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(new KeyManager[]{keyManager}, new TrustManager[]{trustManager}, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Failed to initialize TLS context", e);
        }
    }

    public static @NotNull DynamicTlsContext create(@Nullable X509ExtendedKeyManager keyManager,
                                                    @Nullable X509ExtendedTrustManager trustManager) {
        DynamicTlsContext context = new DynamicTlsContext();
        context.update(keyManager, trustManager);
        return context;
    }

    /**
     * Replaces the client identity and server trust used by handshakes that start from now on.
     */
    public synchronized void update(@Nullable X509ExtendedKeyManager keyManager,
                                    @Nullable X509ExtendedTrustManager trustManager) {
        Material next = new Material(current.get().generation + 1, keyManager, trustManager);
        retained.put(next.generation, next);
        current.set(next);
        retained.keySet().removeIf(generation -> generation <= next.generation - RETAINED_GENERATIONS);
        invalidateCachedSessions();
    }

    public @NotNull SSLContext sslContext() {
        return sslContext;
    }

    public @NotNull SSLSocketFactory socketFactory() {
        return sslContext.getSocketFactory();
    }

    /**
     * The trust manager backing {@link #sslContext()}. HTTP clients such as OkHttp require it
     * alongside {@link #socketFactory()}.
     */
    public @NotNull X509TrustManager trustManager() {
        return trustManager;
    }

    /**
     * The key manager backing {@link #sslContext()}, for callers that build their own context.
     */
    public @NotNull X509ExtendedKeyManager keyManager() {
        return keyManager;
    }

    private void invalidateCachedSessions() {
        SSLSessionContext sessions = sslContext.getClientSessionContext();
        for (Enumeration<byte[]> ids = sessions.getIds(); ids.hasMoreElements(); ) {
            SSLSession session = sessions.getSession(ids.nextElement());
            if (session != null) {
                session.invalidate();
            }
        }
    }

    private static X509ExtendedTrustManager systemDefaultTrustManager() {
        try {
            TrustManagerFactory factory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            for (TrustManager trustManager : factory.getTrustManagers()) {
                if (trustManager instanceof X509ExtendedTrustManager) {
                    return (X509ExtendedTrustManager) trustManager;
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IllegalStateException("Failed to load default trust managers", e);
        }
        throw new IllegalStateException("No default X509ExtendedTrustManager available");
    }

    private static final class Material {
        final long generation;
        final X509ExtendedKeyManager keyManager;
        final X509ExtendedTrustManager trustManager;

        Material(long generation, X509ExtendedKeyManager keyManager, X509ExtendedTrustManager trustManager) {
            this.generation = generation;
            this.keyManager = keyManager;
            this.trustManager = trustManager;
        }
    }

    /**
     * Prefixes every alias it hands out with the generation it came from, and resolves keys and
     * certificate chains against that same generation, so one handshake never mixes identities.
     */
    private final class PinningKeyManager extends X509ExtendedKeyManager {

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            Material m = current.get();
            return m.keyManager == null ? null : pin(m, m.keyManager.chooseClientAlias(keyType, issuers, socket));
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            Material m = current.get();
            return m.keyManager == null ? null : pin(m, m.keyManager.chooseEngineClientAlias(keyType, issuers, engine));
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            Material m = current.get();
            if (m.keyManager == null) {
                return null;
            }
            String[] aliases = m.keyManager.getClientAliases(keyType, issuers);
            if (aliases == null || aliases.length == 0) {
                return null;
            }
            String[] pinned = new String[aliases.length];
            for (int i = 0; i < aliases.length; i++) {
                pinned[i] = pin(m, aliases[i]);
            }
            return pinned;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            Material m = unpin(alias);
            return m == null ? null : m.keyManager.getPrivateKey(unpinnedAlias(alias));
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            Material m = unpin(alias);
            return m == null ? null : m.keyManager.getCertificateChain(unpinnedAlias(alias));
        }

        // Server-side selection is never requested from an HTTP client.
        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }

        private String pin(Material m, String alias) {
            return alias == null ? null : m.generation + PIN_SEPARATOR + alias;
        }

        private Material unpin(String alias) {
            int separator = alias == null ? -1 : alias.indexOf(PIN_SEPARATOR);
            if (separator < 0) {
                return null;
            }
            Material m;
            try {
                m = retained.get(Long.parseLong(alias.substring(0, separator)));
            } catch (NumberFormatException e) {
                return null;
            }
            return m == null || m.keyManager == null ? null : m;
        }

        private String unpinnedAlias(String alias) {
            return alias.substring(alias.indexOf(PIN_SEPARATOR) + 1);
        }
    }

    private final class SwappableTrustManager extends X509ExtendedTrustManager {

        private X509ExtendedTrustManager delegate() {
            X509ExtendedTrustManager tm = current.get().trustManager;
            return tm != null ? tm : defaultTrustManager;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate().checkClientTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
            delegate().checkClientTrusted(chain, authType, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
            delegate().checkClientTrusted(chain, authType, engine);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate().checkServerTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
            delegate().checkServerTrusted(chain, authType, socket);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
            delegate().checkServerTrusted(chain, authType, engine);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate().getAcceptedIssuers();
        }
    }
}
