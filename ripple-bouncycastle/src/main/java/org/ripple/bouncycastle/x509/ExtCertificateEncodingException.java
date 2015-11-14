package org.ripple.bouncycastle.x509;

import java.security.cert.certificateencodingexception;

class extcertificateencodingexception
    extends certificateencodingexception
{
    throwable cause;

    extcertificateencodingexception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
