package org.moorecoinlab.client.util;

import java.io.*;
import java.util.properties;

public class config {
    properties config = new properties();
    private static config instance = new config();

    private config(){
        synchronized (config.class) {
            loadproperties();
        }
    }

    private void loadproperties(){
        string[] filenames = new string[]{"config.properties", "websocket.properties"};
        for(string filename: filenames) {
            file conffile = new file("/etc/" + filename);
            inputstream in;
            if (conffile.exists()) {
                try {
                    in = new fileinputstream(conffile);
                } catch (filenotfoundexception e) {
                    in = getclass().getresourceasstream("/" + filename);
                }
            } else {
                in = getclass().getresourceasstream("/" + filename);
            }
            try {
                if(in != null)
                    config.load(in);
            } catch (ioexception e) {
                e.printstacktrace();
            }
        }
    }

    public static config getinstance() {
        return instance;
    }

    public string getproperty(string key){
        return config.getproperty(key);
    }

    public static void main(string[] args){
        string name = config.getinstance().getproperty("client.name");
        system.out.println(name);
    }

}
