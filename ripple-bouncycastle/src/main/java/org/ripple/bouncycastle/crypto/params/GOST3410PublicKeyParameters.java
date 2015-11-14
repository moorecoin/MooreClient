package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class gost3410publickeyparameters
        extends gost3410keyparameters
{
    private biginteger      y;

    public gost3410publickeyparameters(
        biginteger      y,
        gost3410parameters   params)
    {
        super(false, params);

        this.y = y;
    }

    public biginteger gety()
    {
        return y;
    }
}
