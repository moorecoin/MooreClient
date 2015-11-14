package org.ripple.bouncycastle.pqc.crypto.gmss;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class gmsskeygenerationparameters
    extends keygenerationparameters
{

    private gmssparameters params;

    public gmsskeygenerationparameters(
        securerandom random,
        gmssparameters params)
    {
        // xxx key size?
        super(random, 1);
        this.params = params;
    }

    public gmssparameters getparameters()
    {
        return params;
    }
}
