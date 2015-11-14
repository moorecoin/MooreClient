package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class keyparameter
    implements cipherparameters
{
    private byte[]  key;

    public keyparameter(
        byte[]  key)
    {
        this(key, 0, key.length);
    }

    public keyparameter(
        byte[]  key,
        int     keyoff,
        int     keylen)
    {
        this.key = new byte[keylen];

        system.arraycopy(key, keyoff, this.key, 0, keylen);
    }

    public byte[] getkey()
    {
        return key;
    }
}
