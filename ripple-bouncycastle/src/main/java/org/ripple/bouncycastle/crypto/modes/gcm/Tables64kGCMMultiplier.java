package org.ripple.bouncycastle.crypto.modes.gcm;

import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.arrays;

public class tables64kgcmmultiplier implements gcmmultiplier
{
    private byte[] h;
    private int[][][] m;

    public void init(byte[] h)
    {
        if (m == null)
        {
            m = new int[16][256][4];
        }
        else if (arrays.areequal(this.h, h))
        {
            return;
        }

        this.h = arrays.clone(h);

        // m[0][0] is zeroes;
        gcmutil.asints(h, m[0][128]);

        for (int j = 64; j >= 1; j >>= 1)
        {
            gcmutil.multiplyp(m[0][j + j], m[0][j]);
        }

        int i = 0;
        for (;;)
        {
            for (int j = 2; j < 256; j += j)
            {
                for (int k = 1; k < j; ++k)
                {
                    gcmutil.xor(m[i][j], m[i][k], m[i][j + k]);
                }
            }

            if (++i == 16)
            {
                return;
            }

            // m[i][0] is zeroes;
            for (int j = 128; j > 0; j >>= 1)
            {
                gcmutil.multiplyp8(m[i - 1][j], m[i][j]);
            }
        }
    }

    public void multiplyh(byte[] x)
    {
//      assert x.length == 16;

        int[] z = new int[4];
        for (int i = 15; i >= 0; --i)
        {
//            gcmutil.xor(z, m[i][x[i] & 0xff]);
            int[] m = m[i][x[i] & 0xff];
            z[0] ^= m[0];
            z[1] ^= m[1];
            z[2] ^= m[2];
            z[3] ^= m[3];
        }

        pack.inttobigendian(z, x, 0);
    }
}
