package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.derivationparameters;

/**
 * parameters for mask derivation functions.
 */
public class mgfparameters
    implements derivationparameters
{
    byte[]  seed;

    public mgfparameters(
        byte[]  seed)
    {
        this(seed, 0, seed.length);
    }

    public mgfparameters(
        byte[]  seed,
        int     off,
        int     len)
    {
        this.seed = new byte[len];
        system.arraycopy(seed, off, this.seed, 0, len);
    }

    public byte[] getseed()
    {
        return seed;
    }
}
