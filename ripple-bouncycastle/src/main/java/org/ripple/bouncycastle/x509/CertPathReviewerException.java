package org.ripple.bouncycastle.x509;

import java.security.cert.certpath;

import org.ripple.bouncycastle.i18n.errorbundle;
import org.ripple.bouncycastle.i18n.localizedexception;

public class certpathreviewerexception extends localizedexception
{

    private int index = -1;
    
    private certpath certpath = null;
    
    public certpathreviewerexception(errorbundle errormessage, throwable throwable)
    {
        super(errormessage, throwable);
    }

    public certpathreviewerexception(errorbundle errormessage)
    {
        super(errormessage);
    }

    public certpathreviewerexception(
            errorbundle errormessage, 
            throwable throwable,
            certpath certpath,
            int index)
    {
        super(errormessage, throwable);
        if (certpath == null || index == -1)
        {
            throw new illegalargumentexception();
        }
        if (index < -1 || (certpath != null && index >= certpath.getcertificates().size()))
        {
            throw new indexoutofboundsexception();
        }
        this.certpath = certpath;
        this.index = index;
    }
    
    public certpathreviewerexception(
            errorbundle errormessage, 
            certpath certpath,
            int index)
    {
        super(errormessage);
        if (certpath == null || index == -1)
        {
            throw new illegalargumentexception();
        }
        if (index < -1 || (certpath != null && index >= certpath.getcertificates().size()))
        {
            throw new indexoutofboundsexception();
        }
        this.certpath = certpath;
        this.index = index;
    }
    
    public certpath getcertpath()
    {
        return certpath;
    }
    
    public int getindex()
    {
        return index;
    }

}
