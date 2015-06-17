package it.thomasjohansen.launcher.web.tomcat;

import org.junit.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import static org.junit.Assert.assertTrue;

/**
 * @author thomas@thomasjohansen.it
 */
public class TomcatLauncherTest {

    @Test
    public void whenConnectorPortIsConfiguredThenAListeningSocketOnThatPortIsCreatedOnLaunch() throws Exception {
        final int port = getAvailablePort();
        new TomcatLauncher(TomcatLauncher.configuration().addConnector(port).build()).launch();
        try (Socket socket = new Socket("localhost", port)) {
            assertTrue(socket.isConnected());
        }
    }

    private int getAvailablePort() throws IOException {
        try (ServerSocket ss = new ServerSocket(0)) {
            ss.setReuseAddress(true);
            return ss.getLocalPort();
        }
    }

}
