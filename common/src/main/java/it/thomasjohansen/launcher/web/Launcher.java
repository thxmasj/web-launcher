package it.thomasjohansen.launcher.web;

import java.lang.Exception; /**
 * Launch web applications.
 * @author thomas@thomasjohansen.it
 */
public interface Launcher {

    void launch() throws Exception;

    void awaitTermination();

}
