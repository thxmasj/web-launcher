package it.thomasjohansen.weblauncher;

import java.io.Closeable;
import java.lang.Exception; /**
 * Launch web applications.
 * @author thomas@thomasjohansen.it
 */
public interface Launcher extends Closeable {

    Launcher launch() throws Exception;

    Launcher awaitTermination();

}
