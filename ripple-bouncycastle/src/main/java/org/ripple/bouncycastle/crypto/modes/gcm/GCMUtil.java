package org.ripple.bouncycastle.crypto.modes.gcm;

import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.arrays;

abstract class gcmutil
{
    static byte[] oneasbytes()
    {
        byte[] tmp = new byte[16];
        tmp[0] = (byte)0x80;
        return tmp;
    }

    static int[] oneasints()
    {
        int[] tmp = new int[4];
        tmp[0] = 0x80000000;
        return tmp;
    }

    static byte[] asbytes(int[] ns)
    {
        byte[] output = new byte[16];
        pack.inttobigendian(ns, output, 0);
        return output;
    }

    static int[] asints(byte[] bs)
    {
        int[] output = new int[4];
        pack.bigendiantoint(bs, 0, output);
        return output;
    }

    static void asints(byte[] bs, int[] output)
    {
        pack.bigendiantoint(bs, 0, output);
    }

    static void multiply(byte[] block, byte[] val)
    {
        byte[] tmp = arrays.clone(block);
        byte[] c = new byte[16];

        for (int i = 0; i < 16; ++i)
        {
            byte bits = val[i];
            for (int j = 7; j >= 0; --j)
            {
                if ((bits & (1 << j)) != 0)
                {
                    xor(c, tmp);
                }

                boolean lsb = (tmp[15] & 1) != 0;
                shiftright(tmp);
                if (lsb)
                {
                    // r = new byte[]{ 0xe1, ... };
//                    gcmutil.xor(v, r);
                    tmp[0] ^= (byte)0xe1;
                }
            }
        }

        system.arraycopy(c, 0, block, 0, 16);
    }

    // p is the value with only bit i=1 set
    static void multiplyp(int[] x)
    {
        boolean lsb = (x[3] & 1) != 0;
        shiftright(x);
        if (lsb)
        {
            // r = new int[]{ 0xe1000000, 0, 0, 0 };
//            xor(v, r);
            x[0] ^= 0xe1000000;
        }
    }

    static void multiplyp(int[] x, int[] output)
    {
        boolean lsb = (x[3] & 1) != 0;
        shiftright(x, output);
        if (lsb)
        {
            output[0] ^= 0xe1000000;
        }
    }

    // p is the value with only bit i=1 set
    static void multiplyp8(int[] x)
    {
//        for (int i = 8; i != 0; --i)
//        {
//            multiplyp(x);
//        }

        int lsw = x[3];
        shiftrightn(x, 8);
        for (int i = 7; i >= 0; --i)
        {
            if ((lsw & (1 << i)) != 0)
            {
                x[0] ^= (0xe1000000 >>> (7 - i));
            }
        }
    }

    static void multiplyp8(int[] x, int[] output)
    {
        int lsw = x[3];
        shiftrightn(x, 8, output);
        for (int i = 7; i >= 0; --i)
        {
            if ((lsw & (1 << i)) != 0)
            {
                output[0] ^= (0xe1000000 >>> (7 - i));
            }
        }
    }

    static void shiftright(byte[] block)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i] & 0xff;
            block[i] = (byte) ((b >>> 1) | bit);
            if (++i == 16)
            {
                break;
            }
            bit = (b & 1) << 7;
        }
    }

    static void shiftright(byte[] block, byte[] output)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i] & 0xff;
            output[i] = (byte) ((b >>> 1) | bit);
            if (++i == 16)
            {
                break;
            }
            bit = (b & 1) << 7;
        }
    }

    static void shiftright(int[] block)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i];
            block[i] = (b >>> 1) | bit;
            if (++i == 4)
            {
                break;
            }
            bit = b << 31;
        }
    }

    static void shiftright(int[] block, int[] output)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i];
            output[i] = (b >>> 1) | bit;
            if (++i == 4)
            {
                break;
            }
            bit = b << 31;
        }
    }

    static void shiftrightn(int[] block, int n)
    {
        int i = 0;
        int bits = 0;
        for (;;)
        {
            int b = block[i];
            block[i] = (b >>> n) | bits;
            if (++i == 4)
            {
                break;
            }
            bits = b << (32 - n);
        }
    }

    static void shiftrightn(int[] block, int n, int[] output)
    {
        int i = 0;
        int bits = 0;
        for (;;)
        {
            int b = block[i];
            output[i] = (b >>> n) | bits;
            if (++i == 4)
            {
                break;
            }
            bits = b << (32 - n);
        }
    }

    static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }

    static void xor(byte[] block, byte[] val, int off, int len)
    {
        while (len-- > 0)
        {
            block[len] ^= val[off + len];
        }
    }

    static void xor(byte[] block, byte[] val, byte[] output)
    {
        for (int i = 15; i >= 0; --i)
        {
            output[i] = (byte)(block[i] ^ val[i]);
        }
    }

    static void xor(int[] block, int[] val)
    {
        for (int i = 3; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }

    static void xor(int[] block, int[] val, int[] output)
    {
        for (int i = 3; i >= 0; --i)
        {
            output[i] = block[i] ^ val[i];
        }
    }
}
