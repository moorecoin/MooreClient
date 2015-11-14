package org.ripple.bouncycastle.crypto.params;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class dsakeygenerationparameters
    extends keygenerationparameters
{
    private dsaparameters    params;

    public dsakeygenerationparameters(
        securerandom    random,
        dsaparameters   params)
    {
        super(random, params.getp().bitlength() - 1);

        this.params = params;
    }

    public dsaparameters getparameters()
    {
        return params;
    }
}
