package org.ripple.bouncycastle.i18n;

import java.net.url;
import java.net.urlclassloader;
import java.util.locale;

public class missingentryexception extends runtimeexception 
{

    protected final string resource;
    protected final string key;
    protected final classloader loader;
    protected final locale locale;
    
    private string debugmsg;

    public missingentryexception(string message, string resource, string key, locale locale, classloader loader) 
    {
        super(message);
        this.resource = resource;
        this.key = key;
        this.locale = locale;
        this.loader = loader;
    }
    
    public missingentryexception(string message, throwable cause, string resource, string key, locale locale, classloader loader) 
    {
        super(message, cause);
        this.resource = resource;
        this.key = key;
        this.locale = locale;
        this.loader = loader;
    }

    public string getkey()
    {
        return key;
    }

    public string getresource()
    {
        return resource;
    }
    
    public classloader getclassloader()
    {
        return loader;
    }
    
    public locale getlocale()
    {
        return locale;
    }

    public string getdebugmsg()
    {
        if (debugmsg == null)
        {
            debugmsg = "can not find entry " + key + " in resource file " + resource + " for the locale " + locale + ".";
            if (loader instanceof urlclassloader)
            {
                url[] urls = ((urlclassloader) loader).geturls();
                debugmsg += " the following entries in the classpath were searched: ";
                for (int i = 0; i != urls.length; i++)
                {
                    debugmsg += urls[i] + " ";
                }
            }
        }
        return debugmsg;
    }

}
