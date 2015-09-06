package it.thomasjohansen.launcher.web.tomcat;

import it.thomasjohansen.launcher.web.Launcher;
import it.thomasjohansen.launcher.web.LauncherConfiguration;
import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author thomas@thomasjohansen.it
 */
public class TomcatLauncherTest {

    @Test
    public void whenConnectorPortIsConfiguredThenAListeningSocketOnThatPortIsCreatedOnLaunch() throws Exception {
        int port = findAvailablePort();
        LauncherConfiguration config = TomcatLauncher.configuration().connector(port).build();
        try (@SuppressWarnings("unused")
             Launcher launcher = new TomcatLauncher(config).launch();
             Socket socket = new Socket("localhost", port)) {
            assertTrue(socket.isConnected());
        }
    }

    @Test
    public void whenAddingSecureConnectorTlsIsWorking() throws Exception {
        int port = findAvailablePort();
        trustAllCertificates();
        LauncherConfiguration config = TomcatLauncher.configuration().secureConnector(port, "/tls.jks", "changeit").enableManager().build();
        HttpsURLConnection connection = null;
        try (@SuppressWarnings("unused")
             Launcher launcher = new TomcatLauncher(config).launch()) {
            URL url = new URL("https://localhost:" + port + "/manager");
            connection = (HttpsURLConnection) url.openConnection();
            assertEquals(200, connection.getResponseCode());
            assertEquals("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", connection.getCipherSuite());
        } finally {
            if (connection != null)
                connection.disconnect();
        }
    }

    private int findAvailablePort() throws IOException {
        try (ServerSocket ss = new ServerSocket(0)) {
            ss.setReuseAddress(true);
            return ss.getLocalPort();
        }
    }

    private void trustAllCertificates() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

}
