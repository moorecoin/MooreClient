package org.ripple.bouncycastle.pqc.crypto.mceliece;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class mceliececca2keygenerationparameters
    extends keygenerationparameters
{
    private mceliececca2parameters params;

    public mceliececca2keygenerationparameters(
        securerandom random,
        mceliececca2parameters params)
    {
        // xxx key size?
        super(random, 128);
        this.params = params;
    }

    public mceliececca2parameters getparameters()
    {
        return params;
    }
}
