package org.ripple.bouncycastle.ocsp;

public class ocspexception
    extends exception
{
    exception   e;

    public ocspexception(
        string name)
    {
        super(name);
    }

    public ocspexception(
        string name,
        exception e)
    {
        super(name);

        this.e = e;
    }

    public exception getunderlyingexception()
    {
        return e;
    }

    public throwable getcause()
    {
        return e;
    }
}
