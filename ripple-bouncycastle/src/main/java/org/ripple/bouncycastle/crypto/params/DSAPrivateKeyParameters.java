package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class dsaprivatekeyparameters
    extends dsakeyparameters
{
    private biginteger      x;

    public dsaprivatekeyparameters(
        biginteger      x,
        dsaparameters   params)
    {
        super(true, params);

        this.x = x;
    }   

    public biginteger getx()
    {
        return x;
    }
}
