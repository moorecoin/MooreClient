package org.ripple.bouncycastle.jce.provider;

import org.ripple.bouncycastle.jce.exception.extexception;

public class annotatedexception
    extends exception
    implements extexception
{
    private throwable _underlyingexception;

    annotatedexception(string string, throwable e)
    {
        super(string);

        _underlyingexception = e;
    }

    annotatedexception(string string)
    {
        this(string, null);
    }

    throwable getunderlyingexception()
    {
        return _underlyingexception;
    }

    public throwable getcause()
    {
        return _underlyingexception;
    }
}
