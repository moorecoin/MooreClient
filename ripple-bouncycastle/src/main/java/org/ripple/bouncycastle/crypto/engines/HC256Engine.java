package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * hc-256 is a software-efficient stream cipher created by hongjun wu. it 
 * generates keystream from a 256-bit secret key and a 256-bit initialization 
 * vector.
 * <p>
 * http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc256_p3.pdf
 * </p><p>
 * its brother, hc-128, is a third phase candidate in the estream contest.
 * the algorithm is patent-free. no attacks are known as of today (april 2007). 
 * see
 * 
 * http://www.ecrypt.eu.org/stream/hcp3.html
 * </p>
 */
public class hc256engine
    implements streamcipher
{
    private int[] p = new int[1024];
    private int[] q = new int[1024];
    private int cnt = 0;

    private int step()
    {
        int j = cnt & 0x3ff;
        int ret;
        if (cnt < 1024)
        {
            int x = p[(j - 3 & 0x3ff)];
            int y = p[(j - 1023 & 0x3ff)];
            p[j] += p[(j - 10 & 0x3ff)]
                + (rotateright(x, 10) ^ rotateright(y, 23))
                + q[((x ^ y) & 0x3ff)];

            x = p[(j - 12 & 0x3ff)];
            ret = (q[x & 0xff] + q[((x >> 8) & 0xff) + 256]
                + q[((x >> 16) & 0xff) + 512] + q[((x >> 24) & 0xff) + 768])
                ^ p[j];
        }
        else
        {
            int x = q[(j - 3 & 0x3ff)];
            int y = q[(j - 1023 & 0x3ff)];
            q[j] += q[(j - 10 & 0x3ff)]
                + (rotateright(x, 10) ^ rotateright(y, 23))
                + p[((x ^ y) & 0x3ff)];

            x = q[(j - 12 & 0x3ff)];
            ret = (p[x & 0xff] + p[((x >> 8) & 0xff) + 256]
                + p[((x >> 16) & 0xff) + 512] + p[((x >> 24) & 0xff) + 768])
                ^ q[j];
        }
        cnt = cnt + 1 & 0x7ff;
        return ret;
    }

    private byte[] key, iv;
    private boolean initialised;

    private void init()
    {
        if (key.length != 32 && key.length != 16)
        {
            throw new illegalargumentexception(
                "the key must be 128/256 bits long");
        }

        if (iv.length < 16)
        {
            throw new illegalargumentexception(
                "the iv must be at least 128 bits long");
        }

        if (key.length != 32)
        {
            byte[] k = new byte[32];

            system.arraycopy(key, 0, k, 0, key.length);
            system.arraycopy(key, 0, k, 16, key.length);

            key = k;
        }

        if (iv.length < 32)
        {
            byte[] newiv = new byte[32];

            system.arraycopy(iv, 0, newiv, 0, iv.length);
            system.arraycopy(iv, 0, newiv, iv.length, newiv.length - iv.length);

            iv = newiv;
        }

        cnt = 0;

        int[] w = new int[2560];

        for (int i = 0; i < 32; i++)
        {
            w[i >> 2] |= (key[i] & 0xff) << (8 * (i & 0x3));
        }

        for (int i = 0; i < 32; i++)
        {
            w[(i >> 2) + 8] |= (iv[i] & 0xff) << (8 * (i & 0x3));
        }

        for (int i = 16; i < 2560; i++)
        {
            int x = w[i - 2];
            int y = w[i - 15];
            w[i] = (rotateright(x, 17) ^ rotateright(x, 19) ^ (x >>> 10))
                + w[i - 7]
                + (rotateright(y, 7) ^ rotateright(y, 18) ^ (y >>> 3))
                + w[i - 16] + i;
        }

        system.arraycopy(w, 512, p, 0, 1024);
        system.arraycopy(w, 1536, q, 0, 1024);

        for (int i = 0; i < 4096; i++)
        {
            step();
        }

        cnt = 0;
    }

    public string getalgorithmname()
    {
        return "hc-256";
    }

    /**
     * initialise a hc-256 cipher.
     *
     * @param forencryption whether or not we are for encryption. irrelevant, as
     *                      encryption and decryption are the same.
     * @param params        the parameters required to set up the cipher.
     * @throws illegalargumentexception if the params argument is
     *                                  inappropriate (ie. the key is not 256 bit long).
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
                "invalid parameter passed to hc256 init - "
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

    private static int rotateright(
        int     x,
        int     bits)
    {
        return (x >>> bits) | (x << -bits);
    }
}
