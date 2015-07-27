package it.thomasjohansen.launcher.web.tomcat;

import it.thomasjohansen.launcher.web.ApplicationDescriptor;
import it.thomasjohansen.launcher.web.ConnectorDescriptor;
import it.thomasjohansen.launcher.web.Launcher;
import it.thomasjohansen.launcher.web.LauncherConfiguration;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.Wrapper;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.manager.ManagerServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;

import javax.servlet.ServletException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import static java.lang.System.console;

/**
 * Launch web applications (WAR files) with Tomcat.
 */
public class TomcatLauncher implements Launcher {

    private final Tomcat tomcat = new Tomcat();

    public static LauncherConfiguration.Builder configuration() {
        return LauncherConfiguration.builder();
    }

    public static void main(String[] args) throws Exception {
        LauncherConfiguration configuration;
        if (args.length > 0)
            configuration = configuration().cliArguments(args).build();
        else if (hasManifestEntry()) {
            URL location = TomcatLauncher.class.getProtectionDomain().getCodeSource().getLocation();
            JarFile jarFile = new JarFile(location.getFile());
            Manifest manifest = jarFile.getManifest();
            Attributes attributes = manifest.getMainAttributes();
            String port = attributes.getValue("WebLauncher-Port");
            String keyStorePath = attributes.getValue("WebLauncher-KeyStorePath");
            String contextPath = attributes.getValue("WebLauncher-ContextPath");
            LauncherConfiguration.Builder configBuilder = configuration();
            if (port != null) {
                if (keyStorePath != null) {
                    configBuilder.addSecureConnector(
                            Integer.parseInt(port),
                            keyStorePath,
                            // TODO: Could be read when Tomcat is actually configured - or started - to minimize memory footprint
                            getPrivateKeyPassword()
                    );
                } else {
                    configBuilder.addConnector(Integer.parseInt(port));
                }
            }
            if (contextPath != null) {
                configBuilder.addApplication(contextPath, location.getFile());
            }
            configuration = configBuilder.build();
        } else {
            configuration = configuration().defaults().build();
        }
        new TomcatLauncher(configuration).launch();
    }

    private static boolean hasManifestEntry() throws IOException {
        URL location = TomcatLauncher.class.getProtectionDomain().getCodeSource().getLocation();
        JarFile jarFile = new JarFile(location.getFile());
        Manifest manifest = jarFile.getManifest();
        return manifest != null && manifest.getMainAttributes().getValue("WebLauncher-Port") != null;
    }

    public TomcatLauncher(LauncherConfiguration configuration) throws CertificateException, ServletException, NoSuchAlgorithmException, KeyStoreException, URISyntaxException, IOException {
        configure(configuration);
    }

    private void configure(LauncherConfiguration configuration) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, ServletException, URISyntaxException {
        tomcat.setBaseDir(configuration.getBaseDir().toAbsolutePath().toString());
        for (ConnectorDescriptor connectorDescriptor : configuration.getConnectorDescriptors()) {
            if (connectorDescriptor.getKeyStorePath() != null)
                addSecureConnector(
                        tomcat,
                        connectorDescriptor.getPort(),
                        createPrivateKeyStore(
                                configuration.getBaseDir(),
                                connectorDescriptor.getKeyStorePassword(),
                                connectorDescriptor.getKeyStorePath()
                        ),
                        connectorDescriptor.getKeyStorePassword()
                );
            else
                addConnector(tomcat, connectorDescriptor.getPort());
        }
        for (ApplicationDescriptor applicationDescriptor : configuration.getApplicationDescriptors()) {
            addWebApplication(
                    tomcat,
                    configuration.getBaseDir(),
                    applicationDescriptor.getContextPath(),
                    applicationDescriptor.getLocation()
            );
        }
        // Start all applications in parallel
        tomcat.getHost().setStartStopThreads(configuration.getApplicationDescriptors().size());
        if (configuration.isEnableManager()) {
            addManagerServlet(tomcat, configuration.getManagerContextPath());
        }
        Runtime.getRuntime().addShutdownHook(new WorkFileRemover(configuration.getBaseDir()));
        if (configuration.getClassLoader() != null)
            tomcat.getEngine().setParentClassLoader(configuration.getClassLoader());
    }

    @Override
    public Launcher launch() throws LifecycleException {
        tomcat.start();
        return this;
    }

    @Override
    public Launcher awaitTermination() {
        tomcat.getServer().await();
        return this;
    }

    @Override
    public void close() throws IOException {
        try {
            tomcat.getServer().stop();
        } catch (LifecycleException e) {
            throw new IOException("Failed to stop Tomcat", e);
        }
    }

    private Context addWebApplication(
            Tomcat tomcat,
            Path baseDir,
            String contextPath,
            String location
    ) throws ServletException, IOException, URISyntaxException {
        StandardContext context = (StandardContext)tomcat.addWebapp(contextPath, location);
        handleRunningFromMavenWorkspace(location, context);
        // Note that class loading is extremely slow with unpackWAR=false, so start-up and first request(s) might take
        // long time (up to minutes).
        context.setUnpackWAR(true);
        // Directory "webapps" is not used when unpackWAR is false
        if (context.getUnpackWAR() && !Files.exists(baseDir.resolve("webapps")))
            Files.createDirectory(baseDir.resolve("webapps"));
        return context;
    }

    private void handleRunningFromMavenWorkspace(
            String location,
            StandardContext context
    ) throws URISyntaxException {
        File locationFile = new File(location);
        if (locationFile.getName().equals("classes") && locationFile.getParentFile().getName().equals("target")) {
            // Handle running from Maven workspace.
            // - "target/classes" must be mounted on WEB-INF/classes.
            // - "src/main/webapp" must be mounted on /.
            WebResourceRoot resourceRoot = new StandardRoot(context);
            resourceRoot.addPreResources(
                    new DirResourceSet(
                            resourceRoot,
                            "/WEB-INF/classes",
                            locationFile.getAbsolutePath(),
                            "/"
                    )
            );
            File workspaceRoot = new File(location, "../../src/main/webapp");
            if (workspaceRoot.exists()) {
                resourceRoot.addPreResources(
                        new DirResourceSet(
                                resourceRoot,
                                "/",
                                new URI(workspaceRoot.getAbsolutePath()).normalize().getPath(),
                                "/"
                        )
                );
            }
            context.setResources(resourceRoot);
        }
    }

    private void addManagerServlet(Tomcat tomcat, String contextPath) {
        Context managerContext = tomcat.addContext(contextPath, "/tmp");
        ManagerServlet managerServlet = new ManagerServlet();
        Wrapper wrapper = Tomcat.addServlet(managerContext, "manager", managerServlet);
        wrapper.setLoadOnStartup(1);
        wrapper.addMapping("/*");
        managerServlet.setWrapper(wrapper);
    }

    private void addSecureConnector(
            Tomcat tomcat,
            int port,
            Path keyStorePath,
            String password
    ) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        Connector connector = new Connector();
        connector.setPort(port);
        connector.setSecure(true);
        connector.setScheme("https");
        connector.setAttribute("keystoreFile", keyStorePath.toString());
        connector.setAttribute("keystorePass", password);
        if (keyStorePath.toString().endsWith(".p12"))
            connector.setAttribute("keystoreType", "PKCS12");
        connector.setAttribute("SSLEnabled", "true");
        connector.setAttribute("sslEnabledProtocols", "TLSv1.2");
        connector.setAttribute("sslProtocol", "TLSv1.2");
        tomcat.getService().addConnector(connector);
        tomcat.setConnector(connector);
    }

    private void addConnector(Tomcat tomcat, int port) {
        Connector connector = new Connector();
        connector.setPort(port);
        tomcat.getService().addConnector(connector);
        tomcat.setConnector(connector);
    }

    private static Path createPrivateKeyStore(Path directory, String password, String resource) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return createKeyStore(directory, "privateKeyStore", resource, password);
    }

    private static Path createKeyStore(Path directory, String fileName, String resourceName, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (TomcatLauncher.class.getResourceAsStream(resourceName) == null)
            throw new IllegalArgumentException("Resource «" + resourceName + "» does not exist");
        InputStream in = TomcatLauncher.class.getResourceAsStream(resourceName);
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

    static class WorkFileRemover extends Thread {

        private Path baseDir;

        public WorkFileRemover(Path baseDir) {
            this.baseDir = baseDir;
        }

        @Override
        public void run() {
            try {
                deleteRecursive(baseDir.toFile());
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }

        public boolean deleteRecursive(File path) throws FileNotFoundException{
            if (!path.exists()) throw new FileNotFoundException(path.getAbsolutePath());
            boolean ret = true;
            if (path.isDirectory()){
                File[] files = path.listFiles();
                if (files != null) {
                    for (File f : files) {
                        ret = ret && deleteRecursive(f);
                    }
                }
            }
            return ret && path.delete();
        }

    }

}
