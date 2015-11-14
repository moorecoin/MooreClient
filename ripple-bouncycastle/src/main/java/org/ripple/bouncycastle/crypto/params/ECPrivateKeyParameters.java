package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class ecprivatekeyparameters
    extends eckeyparameters
{
    biginteger d;

    public ecprivatekeyparameters(
        biginteger          d,
        ecdomainparameters  params)
    {
        super(true, params);
        this.d = d;
    }

    public biginteger getd()
    {
        return d;
    }
}
