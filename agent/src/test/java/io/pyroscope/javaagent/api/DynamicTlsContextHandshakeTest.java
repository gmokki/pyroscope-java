package io.pyroscope.javaagent.api;

import io.pyroscope.http.Format;
import io.pyroscope.javaagent.EventType;
import io.pyroscope.javaagent.Snapshot;
import io.pyroscope.javaagent.config.Config;
import io.pyroscope.javaagent.impl.PyroscopeExporter;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Drives real TLS handshakes through the exporter against a server that requires client
 * certificates, and verifies which client certificate the server actually saw.
 */
public class DynamicTlsContextHandshakeTest {
    private static final Logger NOOP_LOGGER = (level, msg, args) -> {};
    private static final char[] PASSWORD = "changeit".toCharArray();

    private HeldCertificate ca;
    private HeldCertificate clientA;
    private HeldCertificate clientB;
    private MockWebServer server;

    @BeforeEach
    void startServer() throws Exception {
        ca = new HeldCertificate.Builder().certificateAuthority(0).commonName("test-ca").build();
        String localhost = InetAddress.getByName("localhost").getCanonicalHostName();
        HeldCertificate serverCert = new HeldCertificate.Builder()
            .signedBy(ca)
            .commonName("localhost")
            .addSubjectAlternativeName(localhost)
            .addSubjectAlternativeName("localhost")
            .build();
        clientA = new HeldCertificate.Builder().signedBy(ca).commonName("client-a").build();
        clientB = new HeldCertificate.Builder().signedBy(ca).commonName("client-b").build();

        HandshakeCertificates serverSide = new HandshakeCertificates.Builder()
            .heldCertificate(serverCert)
            .addTrustedCertificate(ca.certificate())
            .build();
        server = new MockWebServer();
        server.useHttps(serverSide.sslSocketFactory(), false);
        server.requireClientAuth();
        server.start();
    }

    @AfterEach
    void stopServer() throws Exception {
        server.shutdown();
    }

    @Test
    void presentsCurrentClientCertificateAndPicksUpRotation() throws Exception {
        DynamicTlsContext tls = DynamicTlsContext.create(keyManager(clientA), trustManager(ca.certificate()));
        PyroscopeExporter exporter = newExporter(tls);
        try {
            // Close the connection after each response so the next export must handshake again.
            server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_END));
            server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_END));

            exporter.export(snapshot());
            assertEquals(clientA.certificate(), peerCertificate(server.takeRequest(5, TimeUnit.SECONDS)));

            tls.update(keyManager(clientB), trustManager(ca.certificate()));

            exporter.export(snapshot());
            assertEquals(clientB.certificate(), peerCertificate(server.takeRequest(5, TimeUnit.SECONDS)));
        } finally {
            exporter.stop();
        }
    }

    @Test
    void withoutClientCertificateTheServerRejectsTheHandshake() throws Exception {
        DynamicTlsContext tls = DynamicTlsContext.create(null, trustManager(ca.certificate()));
        PyroscopeExporter exporter = newExporter(tls);
        try {
            server.enqueue(new MockResponse());

            exporter.export(snapshot());

            assertEquals(0, server.getRequestCount());
        } finally {
            exporter.stop();
        }
    }

    @Test
    void withDefaultTrustTheClientRejectsTheTestServer() throws Exception {
        DynamicTlsContext tls = DynamicTlsContext.create(keyManager(clientA), null);
        PyroscopeExporter exporter = newExporter(tls);
        try {
            server.enqueue(new MockResponse());

            exporter.export(snapshot());

            assertEquals(0, server.getRequestCount());
        } finally {
            exporter.stop();
        }
    }

    private PyroscopeExporter newExporter(DynamicTlsContext tls) {
        Config config = new Config.Builder()
            .setServerAddress(server.url("/").toString())
            .setApplicationName("test.app")
            .setFormat(Format.OTLP)
            .setIngestMaxRetries(1)
            .build();
        return new PyroscopeExporter(config, NOOP_LOGGER, tls.socketFactory(), tls.trustManager());
    }

    private static Snapshot snapshot() {
        return new Snapshot(Format.OTLP, EventType.CPU, Instant.EPOCH, Instant.EPOCH, new byte[]{1, 2, 3}, null);
    }

    private static Certificate peerCertificate(RecordedRequest request) {
        assertNotNull(request, "server did not receive a request");
        assertNotNull(request.getHandshake(), "request was not made over TLS");
        return request.getHandshake().peerCertificates().get(0);
    }

    private static X509ExtendedKeyManager keyManager(HeldCertificate identity) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", identity.keyPair().getPrivate(), PASSWORD,
            new Certificate[]{identity.certificate()});
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore, PASSWORD);
        return (X509ExtendedKeyManager) factory.getKeyManagers()[0];
    }

    private static X509ExtendedTrustManager trustManager(X509Certificate ca) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", ca);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        return (X509ExtendedTrustManager) factory.getTrustManagers()[0];
    }
}
