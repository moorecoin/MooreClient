package org.ripple.bouncycastle.pqc.crypto.rainbow;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class rainbowkeygenerationparameters
    extends keygenerationparameters
{
    private rainbowparameters params;

    public rainbowkeygenerationparameters(
        securerandom random,
        rainbowparameters params)
    {
        // todo: key size?
        super(random, params.getvi()[params.getvi().length - 1] - params.getvi()[0]);
        this.params = params;
    }

    public rainbowparameters getparameters()
    {
        return params;
    }
}

