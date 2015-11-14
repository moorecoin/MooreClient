package org.ripple.bouncycastle.jce.exception;

import java.security.cert.certificateencodingexception;

public class extcertificateencodingexception
    extends certificateencodingexception
    implements extexception
{
    private throwable cause;

    public extcertificateencodingexception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
