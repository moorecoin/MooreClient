package org.ripple.bouncycastle.pqc.crypto.gmss;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;

public class gmsskeyparameters
    extends asymmetrickeyparameter
{
    private gmssparameters params;

    public gmsskeyparameters(
        boolean isprivate,
        gmssparameters params)
    {
        super(isprivate);
        this.params = params;
    }

    public gmssparameters getparameters()
    {
        return params;
    }
}