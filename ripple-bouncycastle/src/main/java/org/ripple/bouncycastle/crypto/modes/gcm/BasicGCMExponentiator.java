package org.ripple.bouncycastle.crypto.modes.gcm;

import org.ripple.bouncycastle.util.arrays;

public class basicgcmexponentiator implements gcmexponentiator
{
    private byte[] x;

    public void init(byte[] x)
    {
        this.x = arrays.clone(x);
    }

    public void exponentiatex(long pow, byte[] output)
    {
        // initial value is little-endian 1
        byte[] y = gcmutil.oneasbytes();

        if (pow > 0)
        {
            byte[] powx = arrays.clone(x);
            do
            {
                if ((pow & 1l) != 0)
                {
                    gcmutil.multiply(y, powx);
                }
                gcmutil.multiply(powx, powx);
                pow >>>= 1;
            }
            while (pow > 0);
        }

        system.arraycopy(y, 0, output, 0, 16);
    }
}
