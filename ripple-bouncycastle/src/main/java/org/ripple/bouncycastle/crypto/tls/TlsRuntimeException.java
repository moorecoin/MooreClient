package org.ripple.bouncycastle.crypto.tls;

public class tlsruntimeexception
    extends runtimeexception
{
    private static final long serialversionuid = 1928023487348344086l;

    throwable e;

    public tlsruntimeexception(string message, throwable e)
    {
        super(message);

        this.e = e;
    }

    public tlsruntimeexception(string message)
    {
        super(message);
    }

    public throwable getcause()
    {
        return e;
    }
}
