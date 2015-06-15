package it.thomasjohansen.launcher.web;

import java.lang.String;import java.nio.file.Path;

/**
 * Describe a web application connector by its TCP port. If the connector is using TLS a key
 * store path and a password for the key store can be specified.
 * @author thomas@thomasjohansen.it
 */
public class ConnectorDescriptor {

    private int port;
    private Path keyStorePath;
    private String keyStorePassword;

    public ConnectorDescriptor(int port) {
        this.port = port;
    }

    public ConnectorDescriptor(int port, Path keyStorePath, String keyStorePassword) {
        this.port = port;
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
    }

    public int getPort() {
        return port;
    }

    public Path getKeyStorePath() {
        return keyStorePath;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

}
