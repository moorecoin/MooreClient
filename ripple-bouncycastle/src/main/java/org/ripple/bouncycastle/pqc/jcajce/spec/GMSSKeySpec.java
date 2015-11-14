package org.ripple.bouncycastle.pqc.jcajce.spec;

import java.security.spec.keyspec;

import org.ripple.bouncycastle.pqc.crypto.gmss.gmssparameters;

public class gmsskeyspec
    implements keyspec
{
    /**
     * the gmssparameterset
     */
    private gmssparameters gmssparameterset;

    protected gmsskeyspec(gmssparameters gmssparameterset)
    {
        this.gmssparameterset = gmssparameterset;
    }

    /**
     * returns the gmss parameter set
     *
     * @return the gmss parameter set
     */
    public gmssparameters getparameters()
    {
        return gmssparameterset;
    }
}
