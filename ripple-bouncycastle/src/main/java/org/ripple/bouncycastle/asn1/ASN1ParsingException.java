package org.ripple.bouncycastle.asn1;

public class asn1parsingexception
    extends illegalstateexception
{
    private throwable cause;

    public asn1parsingexception(string message)
    {
        super(message);
    }

    public asn1parsingexception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
