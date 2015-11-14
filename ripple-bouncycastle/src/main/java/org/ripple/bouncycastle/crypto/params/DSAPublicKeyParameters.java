package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class dsapublickeyparameters
    extends dsakeyparameters
{
    private biginteger      y;

    public dsapublickeyparameters(
        biginteger      y,
        dsaparameters   params)
    {
        super(false, params);

        this.y = y;
    }   

    public biginteger gety()
    {
        return y;
    }
}
