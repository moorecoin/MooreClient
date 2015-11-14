package org.ripple.bouncycastle.pqc.crypto.mceliece;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;


public class mceliececca2keyparameters
    extends asymmetrickeyparameter
{
    private mceliececca2parameters params;

    public mceliececca2keyparameters(
        boolean isprivate,
        mceliececca2parameters params)
    {
        super(isprivate);
        this.params = params;
    }


    public mceliececca2parameters getparameters()
    {
        return params;
    }

}
