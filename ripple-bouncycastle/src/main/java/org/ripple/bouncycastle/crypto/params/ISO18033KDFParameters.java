package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.derivationparameters;

/**
 * parameters for key derivation functions for iso-18033
 */
public class iso18033kdfparameters
    implements derivationparameters
{
    byte[]  seed;

    public iso18033kdfparameters(
        byte[]  seed)
    {
        this.seed = seed;
    }

    public byte[] getseed()
    {
        return seed;
    }
}
