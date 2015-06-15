package it.thomasjohansen.launcher.web;

import java.lang.String; /**
 * Describe a web application by its context path and location.
 * @author thomas@thomasjohansen.it
 */
public class ApplicationDescriptor {

    private String contextPath;
    private String location;

    public ApplicationDescriptor(String contextPath, String location) {
        this.contextPath = contextPath;
        this.location = location;
    }

    public String getContextPath() {
        return contextPath;
    }

    public String getLocation() {
        return location;
    }

}
