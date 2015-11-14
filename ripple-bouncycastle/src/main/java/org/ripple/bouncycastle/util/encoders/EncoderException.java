package org.ripple.bouncycastle.util.encoders;

public class encoderexception
    extends illegalstateexception
{
    private throwable cause;

    encoderexception(string msg, throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
