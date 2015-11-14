package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class rc2parameters
    implements cipherparameters
{
    private byte[]  key;
    private int     bits;

    public rc2parameters(
        byte[]  key)
    {
        this(key, (key.length > 128) ? 1024 : (key.length * 8));
    }

    public rc2parameters(
        byte[]  key,
        int     bits)
    {
        this.key = new byte[key.length];
        this.bits = bits;

        system.arraycopy(key, 0, this.key, 0, key.length);
    }

    public byte[] getkey()
    {
        return key;
    }

    public int geteffectivekeybits()
    {
        return bits;
    }
}
