package org.ripple.bouncycastle.util.encoders;

public class decoderexception
    extends illegalstateexception
{
    private throwable cause;

    decoderexception(string msg, throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
