package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class gost3410privatekeyparameters
        extends gost3410keyparameters
{
    private biginteger      x;

    public gost3410privatekeyparameters(
        biginteger      x,
        gost3410parameters   params)
    {
        super(true, params);

        this.x = x;
    }

    public biginteger getx()
    {
        return x;
    }
}
