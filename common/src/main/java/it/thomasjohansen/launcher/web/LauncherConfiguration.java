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
    private ClassLoader classLoader;

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

    public ClassLoader getClassLoader() {
        return classLoader;
    }

    public String getManagerContextPath() {
        return managerContextPath;
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

        public Builder addSecureConnector(int port, String keyStorePath, String password) {
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

        @SuppressWarnings("unused")
        public Builder enableManager(String contextPath) {
            instance.enableManager = true;
            instance.managerContextPath = contextPath;
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
                                "/tls.jks",
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
