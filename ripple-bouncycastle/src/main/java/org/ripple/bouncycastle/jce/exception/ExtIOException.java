package org.ripple.bouncycastle.jce.exception;

import java.io.ioexception;

public class extioexception
    extends ioexception
    implements extexception
{
    private throwable cause;

    public extioexception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
