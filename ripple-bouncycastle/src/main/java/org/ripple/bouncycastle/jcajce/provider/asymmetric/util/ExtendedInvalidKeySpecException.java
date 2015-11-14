package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.spec.invalidkeyspecexception;

public class extendedinvalidkeyspecexception
    extends invalidkeyspecexception
{
    private throwable cause;

    public extendedinvalidkeyspecexception(string msg, throwable cause)
    {
        super(msg);

        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
