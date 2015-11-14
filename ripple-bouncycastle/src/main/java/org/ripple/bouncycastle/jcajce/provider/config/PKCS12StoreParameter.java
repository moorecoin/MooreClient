package org.ripple.bouncycastle.jcajce.provider.config;

import java.io.outputstream;
import java.security.keystore;
import java.security.keystore.loadstoreparameter;
import java.security.keystore.protectionparameter;

public class pkcs12storeparameter
    implements loadstoreparameter
{
    private final outputstream out;
    private final protectionparameter protectionparameter;
    private final boolean forderencoding;

    public pkcs12storeparameter(outputstream out, char[] password)
    {
        this(out, password, false);
    }

    public pkcs12storeparameter(outputstream out, protectionparameter protectionparameter)
    {
        this(out, protectionparameter, false);
    }

    public pkcs12storeparameter(outputstream out, char[] password, boolean forderencoding)
    {
        this(out, new keystore.passwordprotection(password), forderencoding);
    }

    public pkcs12storeparameter(outputstream out, protectionparameter protectionparameter, boolean forderencoding)
    {
        this.out = out;
        this.protectionparameter = protectionparameter;
        this.forderencoding = forderencoding;
    }

    public outputstream getoutputstream()
    {
        return out;
    }

    public protectionparameter getprotectionparameter()
    {
        return protectionparameter;
    }

    public boolean isforderencoding()
    {
        return forderencoding;
    }
}
