package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.engines.salsa20engine;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.arrays;

public class scrypt
{
    // todo validate arguments
    public static byte[] generate(byte[] p, byte[] s, int n, int r, int p, int dklen)
    {
        return mfcrypt(p, s, n, r, p, dklen);
    }

    private static byte[] mfcrypt(byte[] p, byte[] s, int n, int r, int p, int dklen)
    {
        int mflenbytes = r * 128;
        byte[] bytes = singleiterationpbkdf2(p, s, p * mflenbytes);

        int[] b = null;

        try
        {
            int blen = bytes.length >>> 2;
            b = new int[blen];

            pack.littleendiantoint(bytes, 0, b);

            int mflenwords = mflenbytes >>> 2;
            for (int boff = 0; boff < blen; boff += mflenwords)
            {
                // todo these can be done in parallel threads
                smix(b, boff, n, r);
            }

            pack.inttolittleendian(b, bytes, 0);

            return singleiterationpbkdf2(p, bytes, dklen);
        }
        finally
        {
            clear(bytes);
            clear(b);
        }
    }

    private static byte[] singleiterationpbkdf2(byte[] p, byte[] s, int dklen)
    {
        pbeparametersgenerator pgen = new pkcs5s2parametersgenerator(new sha256digest());
        pgen.init(p, s, 1);
        keyparameter key = (keyparameter) pgen.generatederivedmacparameters(dklen * 8);
        return key.getkey();
    }

    private static void smix(int[] b, int boff, int n, int r)
    {
        int bcount = r * 32;

        int[] blockx1 = new int[16];
        int[] blockx2 = new int[16];
        int[] blocky = new int[bcount];

        int[] x = new int[bcount];
        int[][] v = new int[n][];

        try
        {
            system.arraycopy(b, boff, x, 0, bcount);

            for (int i = 0; i < n; ++i)
            {
                v[i] = arrays.clone(x);
                blockmix(x, blockx1, blockx2, blocky, r);
            }

            int mask = n - 1;
            for (int i = 0; i < n; ++i)
            {
                int j = x[bcount - 16] & mask;
                xor(x, v[j], 0, x);
                blockmix(x, blockx1, blockx2, blocky, r);
            }

            system.arraycopy(x, 0, b, boff, bcount);
        }
        finally
        {
            clearall(v);
            clearall(new int[][]{ x, blockx1, blockx2, blocky });
        }
    }

    private static void blockmix(int[] b, int[] x1, int[] x2, int[] y, int r)
    {
        system.arraycopy(b, b.length - 16, x1, 0, 16);

        int boff = 0, yoff = 0, halflen = b.length >>> 1;

        for (int i = 2 * r; i > 0; --i)
        {
            xor(x1, b, boff, x2);

            salsa20engine.salsacore(8, x2, x1);
            system.arraycopy(x1, 0, y, yoff, 16);

            yoff = halflen + boff - yoff;
            boff += 16;
        }

        system.arraycopy(y, 0, b, 0, y.length);
    }

    private static void xor(int[] a, int[] b, int boff, int[] output)
    {
        for (int i = output.length - 1; i >= 0; --i)
        {
            output[i] = a[i] ^ b[boff + i];
        }
    }

    private static void clear(byte[] array)
    {
        if (array != null)
        {
            arrays.fill(array, (byte)0);
        }
    }

    private static void clear(int[] array)
    {
        if (array != null)
        {
            arrays.fill(array, 0);
        }
    }

    private static void clearall(int[][] arrays)
    {
        for (int i = 0; i < arrays.length; ++i)
        {
            clear(arrays[i]);
        }
    }
}
