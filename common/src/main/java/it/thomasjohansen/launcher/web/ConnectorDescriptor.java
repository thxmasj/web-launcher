package it.thomasjohansen.launcher.web;

/**
 * Describe a web application connector by its TCP port. If the connector is using TLS a key
 * store path and a password for the key store can be specified.
 * @author thomas@thomasjohansen.it
 */
public class ConnectorDescriptor {

    private int port;
    private String keyStorePath;
    private String keyStorePassword;

    public ConnectorDescriptor(int port) {
        this.port = port;
    }

    public ConnectorDescriptor(int port, String keyStorePath, String keyStorePassword) {
        this.port = port;
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
    }

    public int getPort() {
        return port;
    }

    public String getKeyStorePath() {
        return keyStorePath;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

}
