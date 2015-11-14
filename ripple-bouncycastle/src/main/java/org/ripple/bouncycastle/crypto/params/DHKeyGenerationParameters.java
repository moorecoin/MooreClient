package org.ripple.bouncycastle.crypto.params;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class dhkeygenerationparameters
    extends keygenerationparameters
{
    private dhparameters    params;

    public dhkeygenerationparameters(
        securerandom    random,
        dhparameters    params)
    {
        super(random, getstrength(params));

        this.params = params;
    }

    public dhparameters getparameters()
    {
        return params;
    }

    static int getstrength(dhparameters params)
    {
        return params.getl() != 0 ? params.getl() : params.getp().bitlength();
    }
}
