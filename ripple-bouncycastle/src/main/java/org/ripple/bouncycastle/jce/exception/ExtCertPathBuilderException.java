package org.ripple.bouncycastle.jce.exception;

import java.security.cert.certpath;
import java.security.cert.certpathbuilderexception;

public class extcertpathbuilderexception
    extends certpathbuilderexception
    implements extexception
{
    private throwable cause;

    public extcertpathbuilderexception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public extcertpathbuilderexception(string msg, throwable cause, 
        certpath certpath, int index)
    {
        super(msg, cause);
        this.cause = cause;
    }
    
    public throwable getcause()
    {
        return cause;
    }
}
