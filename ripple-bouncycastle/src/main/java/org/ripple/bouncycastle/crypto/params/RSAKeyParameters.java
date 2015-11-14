package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class rsakeyparameters
    extends asymmetrickeyparameter
{
    private biginteger      modulus;
    private biginteger      exponent;

    public rsakeyparameters(
        boolean     isprivate,
        biginteger  modulus,
        biginteger  exponent)
    {
        super(isprivate);

        this.modulus = modulus;
        this.exponent = exponent;
    }   

    public biginteger getmodulus()
    {
        return modulus;
    }

    public biginteger getexponent()
    {
        return exponent;
    }
}
