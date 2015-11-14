package org.ripple.bouncycastle.pqc.crypto.mceliece;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class mceliecekeygenerationparameters
    extends keygenerationparameters
{
    private mcelieceparameters params;

    public mceliecekeygenerationparameters(
        securerandom random,
        mcelieceparameters params)
    {
        // xxx key size?
        super(random, 256);
        this.params = params;
    }

    public mcelieceparameters getparameters()
    {
        return params;
    }
}
