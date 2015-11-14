package org.ripple.bouncycastle.crypto.modes.gcm;

import java.util.vector;

import org.ripple.bouncycastle.util.arrays;

public class tables1kgcmexponentiator implements gcmexponentiator
{
    // a lookup table of the power-of-two powers of 'x'
    // - lookuppowx2[i] = x^(2^i)
    private vector lookuppowx2;

    public void init(byte[] x)
    {
        if (lookuppowx2 != null && arrays.areequal(x, (byte[])lookuppowx2.elementat(0)))
        {
            return;
        }

        lookuppowx2 = new vector(8);
        lookuppowx2.addelement(arrays.clone(x));
    }

    public void exponentiatex(long pow, byte[] output)
    {
        byte[] y = gcmutil.oneasbytes();
        int bit = 0;
        while (pow > 0)
        {
            if ((pow & 1l) != 0)
            {
                ensureavailable(bit);
                gcmutil.multiply(y, (byte[])lookuppowx2.elementat(bit));
            }
            ++bit;
            pow >>>= 1;
        }

        system.arraycopy(y, 0, output, 0, 16);
    }

    private void ensureavailable(int bit)
    {
        int count = lookuppowx2.size();
        if (count <= bit)
        {
            byte[] tmp = (byte[])lookuppowx2.elementat(count - 1);
            do
            {
                tmp = arrays.clone(tmp);
                gcmutil.multiply(tmp, tmp);
                lookuppowx2.addelement(tmp);
            }
            while (++count <= bit);
        }
    }
}
