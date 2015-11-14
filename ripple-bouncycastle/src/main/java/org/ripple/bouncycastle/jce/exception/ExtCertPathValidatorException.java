package org.ripple.bouncycastle.jce.exception;

import java.security.cert.certpath;
import java.security.cert.certpathvalidatorexception;

public class extcertpathvalidatorexception
    extends certpathvalidatorexception
    implements extexception
{

    private throwable cause;

    public extcertpathvalidatorexception(string message, throwable cause)
    {
        super(message);
        this.cause = cause;
    }

    public extcertpathvalidatorexception(string msg, throwable cause, 
        certpath certpath, int index)
    {
        super(msg, cause, certpath, index);
        this.cause = cause;
    }
    
    public throwable getcause()
    {
        return cause;
    }
}
