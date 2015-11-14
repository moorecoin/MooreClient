package org.moorecoinlab.client;

import java.io.*;
import java.util.properties;

/**
 */
public class config {
    properties config = new properties();
    private static config instance = new config();

    private config() {
        synchronized (config.class) {
            loadproperties();
        }
    }

    private void loadproperties() {
        string[] filenames = new string[]{"moorecoin.properties", "moorecoin.properties"};
        for (string filename : filenames) {
            inputstream in;
            in = getclass().getresourceasstream("/" + filename);
            try {
                if (in != null) {
                    system.out.println("config.loadproperties():" + filename);
                    config.load(in);
                    break;
                }
            } catch (ioexception e) {
                e.printstacktrace();
            }
        }
    }

    public static config getinstance() {
        return instance;
    }

    public string getproperty(string key) {
        return config.getproperty(key);
    }

}
