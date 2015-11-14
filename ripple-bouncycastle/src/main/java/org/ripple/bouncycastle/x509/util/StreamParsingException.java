package org.ripple.bouncycastle.x509.util;

public class streamparsingexception 
    extends exception
{
    throwable _e;

    public streamparsingexception(string message, throwable e)
    {
        super(message);
        _e = e;
    }

    public throwable getcause()
    {
        return _e;
    }
}
