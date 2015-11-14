package org.ripple.bouncycastle.crypto.params;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class elgamalkeygenerationparameters
    extends keygenerationparameters
{
    private elgamalparameters    params;

    public elgamalkeygenerationparameters(
        securerandom        random,
        elgamalparameters   params)
    {
        super(random, getstrength(params));

        this.params = params;
    }

    public elgamalparameters getparameters()
    {
        return params;
    }

    static int getstrength(elgamalparameters params)
    {
        return params.getl() != 0 ? params.getl() : params.getp().bitlength();
    }
}
