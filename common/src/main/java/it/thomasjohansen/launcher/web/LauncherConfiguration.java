package it.thomasjohansen.launcher.web;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.Integer;import java.lang.String;import java.lang.System;import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.System.console;

/**
 * Configure web applications.
 * @author thomas@thomasjohansen.it
 */
public class LauncherConfiguration {

    private Path baseDir;
    private List<ConnectorDescriptor> connectorDescriptors = new ArrayList<>();
    private List<ApplicationDescriptor> applicationDescriptors = new ArrayList<>();
    private boolean enableManager;
    private String managerContextPath = "/manager";

    private LauncherConfiguration() {
        // Only builder should use constructor.
    }

    public Path getBaseDir() {
        return baseDir;
    }

    public List<ConnectorDescriptor> getConnectorDescriptors() {
        return connectorDescriptors;
    }

    public List<ApplicationDescriptor> getApplicationDescriptors() {
        return applicationDescriptors;
    }

    public boolean isEnableManager() {
        return enableManager;
    }

    public String getManagerContextPath() {
        return managerContextPath;
    }

    private static Path createPrivateKeyStore(Path directory, String password, String resource) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return createKeyStore(directory, "privateKeyStore", resource, password);
    }

    private static Path createKeyStore(Path directory, String fileName, String resourceName, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        InputStream in = LauncherConfiguration.class.getResourceAsStream(resourceName);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(in, password.toCharArray());
        Path file = directory.resolve(fileName);
        FileOutputStream out = new FileOutputStream(file.toFile());
        keyStore.store(out, password.toCharArray());
        return file.toAbsolutePath();
    }

    private static String getPrivateKeyPassword() {
        return System.getProperty("javax.net.ssl.keyStorePassword",
                console() != null
                        ? String.valueOf(console().readPassword("Private key password> "))
                        : "changeit");
    }

    public static Builder builder() {
        return new Builder(new LauncherConfiguration());
    }

    public static class Builder {
        private LauncherConfiguration instance;

        public Builder(LauncherConfiguration instance) {
            this.instance = instance;
        }

        public Builder addConnector(int port) {
            instance.connectorDescriptors.add(new ConnectorDescriptor(port));
            return this;
        }

        public Builder addSecureConnector(int port, Path keyStorePath, String password) {
            instance.connectorDescriptors.add(new ConnectorDescriptor(port, keyStorePath, password));
            return this;
        }

        public Builder addApplication(String contextPath, String location) {
            instance.applicationDescriptors.add(new ApplicationDescriptor(
                    contextPath,
                    location
            ));
            return this;
        }

        public Builder enableManager() {
            instance.enableManager = true;
            instance.managerContextPath = "/manager";
            return this;
        }

        public Builder enableManager(String contextPath) {
            instance.enableManager = true;
            instance.managerContextPath = contextPath;
            return this;
        }

        public Builder baseDir(Path baseDir) {
            instance.baseDir = baseDir;
            return this;
        }

        public Builder defaults() {
            addConnector(8080)
                    .addApplication(
                            "",
                            LauncherConfiguration.class.getProtectionDomain().getCodeSource().getLocation().getFile()
                    )
                    .enableManager();
            return this;
        }

        public Builder cliArguments(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
            List<String> arguments = Arrays.asList(args);
            Path baseDir = Files.createTempDirectory("Launcher");
            baseDir(baseDir).enableManager();
            for (String argument : arguments) {
                if (argument.matches("\\d+")) {
                    if (LauncherConfiguration.class.getResourceAsStream("/tls.jks") != null) {
                        String keyStorePassword = getPrivateKeyPassword();
                        addSecureConnector(
                                Integer.parseInt(argument),
                                createPrivateKeyStore(
                                        baseDir,
                                        keyStorePassword,
                                        "/tls.jks"
                                ),
                                keyStorePassword
                        );
                    } else
                        addConnector(Integer.parseInt(argument));
                } else if (argument.matches("/.*=.*\\.war")) {
                    addApplication(argument.split("=")[0], argument.split("=")[1]);
                } else {
                    addApplication(
                            argument,
                            LauncherConfiguration.class.getProtectionDomain().getCodeSource().getLocation().getFile()
                    );
                }
            }
            return this;
        }

        public LauncherConfiguration build() throws IOException {
            if (instance.baseDir == null)
                instance.baseDir = Files.createTempDirectory("Launcher");
            return instance;
        }

    }

}
