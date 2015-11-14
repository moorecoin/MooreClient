package org.ripple.bouncycastle.pqc.crypto.mceliece;

import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;


public class mceliecekeyparameters
    extends asymmetrickeyparameter
{
    private mcelieceparameters params;

    public mceliecekeyparameters(
        boolean isprivate,
        mcelieceparameters params)
    {
        super(isprivate);
        this.params = params;
    }


    public mcelieceparameters getparameters()
    {
        return params;
    }

}
