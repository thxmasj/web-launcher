package it.thomasjohansen.launcher.web;

import java.io.IOException;
import java.lang.Integer;import java.lang.String;import java.lang.System;import java.nio.file.Files;
import java.nio.file.Path;
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
    private boolean enableCluster;
    private ClassLoader classLoader;

    private LauncherConfiguration() {
        // Only builder should use constructor.
    }

    public Path baseDir() {
        return baseDir;
    }

    public List<ConnectorDescriptor> connectorDescriptors() {
        return connectorDescriptors;
    }

    public List<ApplicationDescriptor> applicationDescriptors() {
        return applicationDescriptors;
    }

    public boolean enableManager() {
        return enableManager;
    }

    public boolean enableCluster() {
        return enableCluster;
    }

    public ClassLoader classLoader() {
        return classLoader;
    }

    public String managerContextPath() {
        return managerContextPath;
    }

    private static String privateKeyPassword() {
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

        public Builder connector(int port) {
            instance.connectorDescriptors.add(new ConnectorDescriptor(port));
            return this;
        }

        public Builder secureConnector(int port, String keyStorePath, String password) {
            instance.connectorDescriptors.add(new ConnectorDescriptor(port, keyStorePath, password));
            return this;
        }

        public Builder application(String contextPath, String location) {
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

        @SuppressWarnings("unused")
        public Builder enableManager(String contextPath) {
            instance.enableManager = true;
            instance.managerContextPath = contextPath;
            return this;
        }

        public Builder enableCluster() {
            instance.enableCluster = true;
            return this;
        }

        public Builder baseDir(Path baseDir) {
            instance.baseDir = baseDir;
            return this;
        }

        @SuppressWarnings("unused")
        public Builder classLoader(ClassLoader classLoader) {
            instance.classLoader = classLoader;
            return this;
        }

        public Builder defaults() {
            connector(8080)
                    .application(
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
                        String keyStorePassword = privateKeyPassword();
                        secureConnector(
                                Integer.parseInt(argument),
                                "/tls.jks",
                                keyStorePassword
                        );
                    } else
                        connector(Integer.parseInt(argument));
                } else if (argument.matches("/.*=.*\\.war")) {
                    application(argument.split("=")[0], argument.split("=")[1]);
                } else {
                    application(
                            argument,
                            LauncherConfiguration.class.getProtectionDomain().getCodeSource().getLocation().getFile()
                    );
                }
            }
            return this;
        }

        public LauncherConfiguration build() {
            if (instance.baseDir == null) {
                try {
                    instance.baseDir = Files.createTempDirectory("Launcher");
                } catch (IOException e) {
                    throw new RuntimeException("Failed to create base directory", e);
                }
            }
            return instance;
        }

    }

}
