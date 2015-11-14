package org.ripple.bouncycastle.util;

public class storeexception
    extends runtimeexception
{
    private throwable _e;

    public storeexception(string s, throwable e)
    {
        super(s);
        _e = e;
    }

    public throwable getcause()
    {
        return _e;
    }
}
