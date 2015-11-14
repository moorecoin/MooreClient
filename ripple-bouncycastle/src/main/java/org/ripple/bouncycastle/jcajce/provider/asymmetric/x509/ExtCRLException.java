package org.ripple.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.crlexception;

class extcrlexception
    extends crlexception
{
    throwable cause;

    extcrlexception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
