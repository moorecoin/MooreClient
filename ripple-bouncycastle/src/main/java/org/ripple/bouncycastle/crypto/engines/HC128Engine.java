package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * hc-128 is a software-efficient stream cipher created by hongjun wu. it
 * generates keystream from a 128-bit secret key and a 128-bit initialization
 * vector.
 * <p>
 * http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
 * </p><p>
 * it is a third phase candidate in the estream contest, and is patent-free.
 * no attacks are known as of today (april 2007). see
 *
 * http://www.ecrypt.eu.org/stream/hcp3.html
 * </p>
 */
public class hc128engine
    implements streamcipher
{
    private int[] p = new int[512];
    private int[] q = new int[512];
    private int cnt = 0;

    private static int f1(int x)
    {
        return rotateright(x, 7) ^ rotateright(x, 18)
            ^ (x >>> 3);
    }

    private static int f2(int x)
    {
        return rotateright(x, 17) ^ rotateright(x, 19)
            ^ (x >>> 10);
    }

    private int g1(int x, int y, int z)
    {
        return (rotateright(x, 10) ^ rotateright(z, 23))
            + rotateright(y, 8);
    }

    private int g2(int x, int y, int z)
    {
        return (rotateleft(x, 10) ^ rotateleft(z, 23)) + rotateleft(y, 8);
    }

    private static int rotateleft(
        int     x,
        int     bits)
    {
        return (x << bits) | (x >>> -bits);
    }

    private static int rotateright(
        int     x,
        int     bits)
    {
        return (x >>> bits) | (x << -bits);
    }

    private int h1(int x)
    {
        return q[x & 0xff] + q[((x >> 16) & 0xff) + 256];
    }

    private int h2(int x)
    {
        return p[x & 0xff] + p[((x >> 16) & 0xff) + 256];
    }

    private static int mod1024(int x)
    {
        return x & 0x3ff;
    }

    private static int mod512(int x)
    {
        return x & 0x1ff;
    }

    private static int dim(int x, int y)
    {
        return mod512(x - y);
    }

    private int step()
    {
        int j = mod512(cnt);
        int ret;
        if (cnt < 512)
        {
            p[j] += g1(p[dim(j, 3)], p[dim(j, 10)], p[dim(j, 511)]);
            ret = h1(p[dim(j, 12)]) ^ p[j];
        }
        else
        {
            q[j] += g2(q[dim(j, 3)], q[dim(j, 10)], q[dim(j, 511)]);
            ret = h2(q[dim(j, 12)]) ^ q[j];
        }
        cnt = mod1024(cnt + 1);
        return ret;
    }

    private byte[] key, iv;
    private boolean initialised;

    private void init()
    {
        if (key.length != 16)
        {
            throw new java.lang.illegalargumentexception(
                "the key must be 128 bits long");
        }

        cnt = 0;

        int[] w = new int[1280];

        for (int i = 0; i < 16; i++)
        {
            w[i >> 2] |= (key[i] & 0xff) << (8 * (i & 0x3));
        }
        system.arraycopy(w, 0, w, 4, 4);

        for (int i = 0; i < iv.length && i < 16; i++)
        {
            w[(i >> 2) + 8] |= (iv[i] & 0xff) << (8 * (i & 0x3));
        }
        system.arraycopy(w, 8, w, 12, 4);

        for (int i = 16; i < 1280; i++)
        {
            w[i] = f2(w[i - 2]) + w[i - 7] + f1(w[i - 15]) + w[i - 16] + i;
        }

        system.arraycopy(w, 256, p, 0, 512);
        system.arraycopy(w, 768, q, 0, 512);

        for (int i = 0; i < 512; i++)
        {
            p[i] = step();
        }
        for (int i = 0; i < 512; i++)
        {
            q[i] = step();
        }

        cnt = 0;
    }

    public string getalgorithmname()
    {
        return "hc-128";
    }

    /**
     * initialise a hc-128 cipher.
     *
     * @param forencryption whether or not we are for encryption. irrelevant, as
     *                      encryption and decryption are the same.
     * @param params        the parameters required to set up the cipher.
     * @throws illegalargumentexception if the params argument is
     *                                  inappropriate (ie. the key is not 128 bit long).
     */
    public void init(boolean forencryption, cipherparameters params)
        throws illegalargumentexception
    {
        cipherparameters keyparam = params;

        if (params instanceof parameterswithiv)
        {
            iv = ((parameterswithiv)params).getiv();
            keyparam = ((parameterswithiv)params).getparameters();
        }
        else
        {
            iv = new byte[0];
        }

        if (keyparam instanceof keyparameter)
        {
            key = ((keyparameter)keyparam).getkey();
            init();
        }
        else
        {
            throw new illegalargumentexception(
                "invalid parameter passed to hc128 init - "
                    + params.getclass().getname());
        }

        initialised = true;
    }

    private byte[] buf = new byte[4];
    private int idx = 0;

    private byte getbyte()
    {
        if (idx == 0)
        {
            int step = step();
            buf[0] = (byte)(step & 0xff);
            step >>= 8;
            buf[1] = (byte)(step & 0xff);
            step >>= 8;
            buf[2] = (byte)(step & 0xff);
            step >>= 8;
            buf[3] = (byte)(step & 0xff);
        }
        byte ret = buf[idx];
        idx = idx + 1 & 0x3;
        return ret;
    }

    public void processbytes(byte[] in, int inoff, int len, byte[] out,
                             int outoff) throws datalengthexception
    {
        if (!initialised)
        {
            throw new illegalstateexception(getalgorithmname()
                + " not initialised");
        }

        if ((inoff + len) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + len) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        for (int i = 0; i < len; i++)
        {
            out[outoff + i] = (byte)(in[inoff + i] ^ getbyte());
        }
    }

    public void reset()
    {
        idx = 0;
        init();
    }

    public byte returnbyte(byte in)
    {
        return (byte)(in ^ getbyte());
    }
}
