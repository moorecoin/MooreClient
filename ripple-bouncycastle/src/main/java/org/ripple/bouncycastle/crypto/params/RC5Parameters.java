package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class rc5parameters
    implements cipherparameters
{
    private byte[]  key;
    private int     rounds;

    public rc5parameters(
        byte[]  key,
        int     rounds)
    {
        if (key.length > 255)
        {
            throw new illegalargumentexception("rc5 key length can be no greater than 255");
        }

        this.key = new byte[key.length];
        this.rounds = rounds;

        system.arraycopy(key, 0, this.key, 0, key.length);
    }

    public byte[] getkey()
    {
        return key;
    }

    public int getrounds()
    {
        return rounds;
    }
}
