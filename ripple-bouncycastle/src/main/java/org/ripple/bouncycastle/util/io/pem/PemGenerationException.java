package org.ripple.bouncycastle.util.io.pem;

import java.io.ioexception;

public class pemgenerationexception
    extends ioexception
{
    private throwable cause;

    public pemgenerationexception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public pemgenerationexception(string message)
    {
        super(message);
    }

    public throwable getcause()
    {
        return cause;
    }
}
