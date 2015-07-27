package it.thomasjohansen.launcher.web.jetty;

import it.thomasjohansen.launcher.web.ApplicationDescriptor;
import it.thomasjohansen.launcher.web.ConnectorDescriptor;
import it.thomasjohansen.launcher.web.Launcher;
import it.thomasjohansen.launcher.web.LauncherConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.webapp.Configuration;
import org.eclipse.jetty.webapp.WebAppContext;

import javax.servlet.ServletException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static java.lang.System.console;

/**
 * Launch web applications (WAR files) with Jetty.
 */
public class JettyLauncher implements Launcher {

    private final LauncherConfiguration configuration;
    private final Server server = new Server();

    public static LauncherConfiguration.Builder configuration() {
        return LauncherConfiguration.builder();
    }

    public static void main(String[] args) throws Exception {
        LauncherConfiguration configuration;
        if (args.length > 0)
            configuration = configuration().cliArguments(args).build();
        else
            configuration = configuration().defaults().build();
        new JettyLauncher(configuration).launch();
    }

    public JettyLauncher(LauncherConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public Launcher launch() throws Exception {
        //server.setBaseDir(baseDir.toAbsolutePath().toString());
        for (ConnectorDescriptor connectorDescriptor : configuration.getConnectorDescriptors()) {
            if (connectorDescriptor.getKeyStorePath() != null)
                addSecureConnector(server, connectorDescriptor.getPort(), connectorDescriptor.getKeyStorePath());
            else
                addConnector(server, connectorDescriptor.getPort());
        }
        for (ApplicationDescriptor applicationDescriptor : configuration.getApplicationDescriptors()) {
            addWebApplication(
                    server,
                    configuration.getBaseDir(),
                    applicationDescriptor.getContextPath(),
                    applicationDescriptor.getLocation()
            );
        }
        // Start all webapps in parallell
        //server.getHost().setStartStopThreads(applicationDescriptors.size());
        if (configuration.isEnableManager()) {
            //addManagerServlet(server, managerContextPath);
        }
        // Enable servlet specification annotations
        Configuration.ClassList classlist = Configuration.ClassList
                .setServerDefault(server);
        classlist.addAfter(
                org.eclipse.jetty.webapp.FragmentConfiguration.class.getName(),
                org.eclipse.jetty.plus.webapp.EnvConfiguration.class.getName(),
                org.eclipse.jetty.plus.webapp.PlusConfiguration.class.getName()
        );
        classlist.addBefore(
                org.eclipse.jetty.webapp.JettyWebXmlConfiguration.class.getName(),
                org.eclipse.jetty.annotations.AnnotationConfiguration.class.getName()
        );

        //Runtime.getRuntime().addShutdownHook(new WorkFileRemover(baseDir));
        server.start();
        return this;
    }

    @Override
    public Launcher awaitTermination() {
        try {
            server.getServer().join();
        } catch (InterruptedException e) {
            throw new RuntimeException("Failed to await termination");
        }
        return this;
    }

    @Override
    public void close() throws IOException {
        try {
            server.getServer().stop();
        } catch (Exception e) {
            throw new IOException("Failed to stop Jetty", e);
        }
    }

    private void addWebApplication(
            Server server,
            Path baseDir,
            String contextPath,
            String location
    ) throws ServletException, IOException, URISyntaxException {
        WebAppContext context = new WebAppContext();
        context.setContextPath(contextPath);
        context.setWar(location);
        server.setHandler(context);
        //handleRunningFromMavenWorkspace(location, context);
        // Note that class loading is extremely slow with unpackWAR=false, so start-up and first request(s) might take
        // long time (up to minutes).
        //context.setUnpackWAR(true);
        // Directory "webapps" is not used when unpackWAR is false
        //if (context.getUnpackWAR() && !Files.exists(baseDir.resolve("webapps")))
        //    Files.createDirectory(baseDir.resolve("webapps"));
        //return context;
    }

    private String createKeyStore(Path directory, String fileName, String resourceName, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        InputStream in = getClass().getResourceAsStream(resourceName);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(in, password.toCharArray());
        Path file = directory.resolve(fileName);
        FileOutputStream out = new FileOutputStream(file.toFile());
        keyStore.store(out, password.toCharArray());
        return file.toAbsolutePath().toString();
    }

    private String getPrivateKeyPassword() {
        return System.getProperty("javax.net.ssl.keyStorePassword",
                console() != null
                        ? String.valueOf(console().readPassword("Private key password> "))
                        : "changeit");
    }

    private void addSecureConnector(
            Server server,
            int port,
            String keyStorePath
    ) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        throw new UnsupportedOperationException();
    }

    private void addConnector(Server server, int port) {
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(port);
        server.addConnector(connector);
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
