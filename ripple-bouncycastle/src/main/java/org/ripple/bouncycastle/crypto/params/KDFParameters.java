package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.derivationparameters;

/**
 * parameters for key derivation functions for ieee p1363a
 */
public class kdfparameters
    implements derivationparameters
{
    byte[]  iv;
    byte[]  shared;

    public kdfparameters(
        byte[]  shared,
        byte[]  iv)
    {
        this.shared = shared;
        this.iv = iv;
    }

    public byte[] getsharedsecret()
    {
        return shared;
    }

    public byte[] getiv()
    {
        return iv;
    }
}
