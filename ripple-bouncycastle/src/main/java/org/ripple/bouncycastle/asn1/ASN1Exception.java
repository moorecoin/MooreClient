package org.ripple.bouncycastle.asn1;

import java.io.ioexception;

public class asn1exception
    extends ioexception
{
    private throwable cause;

    asn1exception(string message)
    {
        super(message);
    }

    asn1exception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
