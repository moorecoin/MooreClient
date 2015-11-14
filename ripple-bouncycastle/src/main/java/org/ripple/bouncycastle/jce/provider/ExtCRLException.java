package org.ripple.bouncycastle.jce.provider;

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
