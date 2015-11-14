package org.ripple.bouncycastle.jce.provider;

import java.io.outputstream;
import java.security.keystore;
import java.security.keystore.loadstoreparameter;
import java.security.keystore.protectionparameter;

/**
 * @deprecated use org.bouncycastle.jcajce.config.pkcs12storeparameter
 */
public class jdkpkcs12storeparameter implements loadstoreparameter
{
    private outputstream outputstream;
    private protectionparameter protectionparameter;
    private boolean usederencoding;

    public outputstream getoutputstream()
    {
        return outputstream;
    }

    public protectionparameter getprotectionparameter()
    {
        return protectionparameter;
    }

    public boolean isusederencoding()
    {
        return usederencoding;
    }

    public void setoutputstream(outputstream outputstream)
    {
        this.outputstream = outputstream;
    }

    public void setpassword(char[] password)
    {
        this.protectionparameter = new keystore.passwordprotection(password);
    }

    public void setprotectionparameter(protectionparameter protectionparameter)
    {
        this.protectionparameter = protectionparameter;
    }

    public void setusederencoding(boolean usederencoding)
    {
        this.usederencoding = usederencoding;
    }
}
