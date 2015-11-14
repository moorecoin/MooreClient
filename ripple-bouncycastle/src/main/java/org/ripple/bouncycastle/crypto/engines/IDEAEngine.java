package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * a class that provides a basic international data encryption algorithm (idea) engine.
 * <p>
 * this implementation is based on the "howto: international data encryption algorithm"
 * implementation summary by fauzan mirza (f.u.mirza@sheffield.ac.uk). (baring 1 typo at the
 * end of the mulinv function!).
 * <p>
 * it can be found at ftp://ftp.funet.fi/pub/crypt/cryptography/symmetric/idea/
 * <p>
 * note 1: this algorithm is patented in the usa, japan, and europe including
 * at least austria, france, germany, italy, netherlands, spain, sweden, switzerland
 * and the united kingdom. non-commercial use is free, however any commercial
 * products are liable for royalties. please see
 * <a href="http://www.mediacrypt.com">www.mediacrypt.com</a> for
 * further details. this announcement has been included at the request of
 * the patent holders.
 * <p>
 * note 2: due to the requests concerning the above, this algorithm is now only
 * included in the extended bouncy castle provider and jce signed jars. it is
 * not included in the default distributions.
 */
public class ideaengine
    implements blockcipher
{
    protected static final int  block_size = 8;

    private int[]               workingkey = null;

    /**
     * standard constructor.
     */
    public ideaengine()
    {
    }

    /**
     * initialise an idea cipher.
     *
     * @param forencryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean           forencryption,
        cipherparameters  params)
    {
        if (params instanceof keyparameter)
        {
            workingkey = generateworkingkey(forencryption,
                                  ((keyparameter)params).getkey());
            return;
        }

        throw new illegalargumentexception("invalid parameter passed to idea init - " + params.getclass().getname());
    }

    public string getalgorithmname()
    {
        return "idea";
    }

    public int getblocksize()
    {
        return block_size;
    }

    public int processblock(
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
    {
        if (workingkey == null)
        {
            throw new illegalstateexception("idea engine not initialised");
        }

        if ((inoff + block_size) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + block_size) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }

        ideafunc(workingkey, in, inoff, out, outoff);

        return block_size;
    }

    public void reset()
    {
    }

    private static final int    mask = 0xffff;
    private static final int    base = 0x10001;

    private int bytestoword(
        byte[]  in,
        int     inoff)
    {
        return ((in[inoff] << 8) & 0xff00) + (in[inoff + 1] & 0xff);
    }

    private void wordtobytes(
        int     word,
        byte[]  out,
        int     outoff)
    {
        out[outoff] = (byte)(word >>> 8);
        out[outoff + 1] = (byte)word;
    }

    /**
     * return x = x * y where the multiplication is done modulo
     * 65537 (0x10001) (as defined in the idea specification) and
     * a zero input is taken to be 65536 (0x10000).
     *
     * @param x the x value
     * @param y the y value
     * @return x = x * y
     */
    private int mul(
        int x,
        int y)
    {
        if (x == 0)
        {
            x = (base - y);
        }
        else if (y == 0)
        {
            x = (base - x);
        }
        else
        {
            int     p = x * y;

            y = p & mask;
            x = p >>> 16;
            x = y - x + ((y < x) ? 1 : 0);
        }

        return x & mask;
    }

    private void ideafunc(
        int[]   workingkey,
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        int     x0, x1, x2, x3, t0, t1;
        int     keyoff = 0;

        x0 = bytestoword(in, inoff);
        x1 = bytestoword(in, inoff + 2);
        x2 = bytestoword(in, inoff + 4);
        x3 = bytestoword(in, inoff + 6);

        for (int round = 0; round < 8; round++)
        {
            x0 = mul(x0, workingkey[keyoff++]);
            x1 += workingkey[keyoff++];
            x1 &= mask;
            x2 += workingkey[keyoff++];
            x2 &= mask;
            x3 = mul(x3, workingkey[keyoff++]);

            t0 = x1;
            t1 = x2;
            x2 ^= x0;
            x1 ^= x3;

            x2 = mul(x2, workingkey[keyoff++]);
            x1 += x2;
            x1 &= mask;

            x1 = mul(x1, workingkey[keyoff++]);
            x2 += x1;
            x2 &= mask;

            x0 ^= x1;
            x3 ^= x2;
            x1 ^= t1;
            x2 ^= t0;
        }

        wordtobytes(mul(x0, workingkey[keyoff++]), out, outoff);
        wordtobytes(x2 + workingkey[keyoff++], out, outoff + 2);  /* nb: order */
        wordtobytes(x1 + workingkey[keyoff++], out, outoff + 4);
        wordtobytes(mul(x3, workingkey[keyoff]), out, outoff + 6);
    }

    /**
     * the following function is used to expand the user key to the encryption
     * subkey. the first 16 bytes are the user key, and the rest of the subkey
     * is calculated by rotating the previous 16 bytes by 25 bits to the left,
     * and so on until the subkey is completed.
     */
    private int[] expandkey(
        byte[]  ukey)
    {
        int[]   key = new int[52];

        if (ukey.length < 16)
        {
            byte[]  tmp = new byte[16];

            system.arraycopy(ukey, 0, tmp, tmp.length - ukey.length, ukey.length);

            ukey = tmp;
        }

        for (int i = 0; i < 8; i++)
        {
            key[i] = bytestoword(ukey, i * 2);
        }

        for (int i = 8; i < 52; i++)
        {
            if ((i & 7) < 6)
            {
                key[i] = ((key[i - 7] & 127) << 9 | key[i - 6] >> 7) & mask;
            }
            else if ((i & 7) == 6)
            {
                key[i] = ((key[i - 7] & 127) << 9 | key[i - 14] >> 7) & mask;
            }
            else
            {
                key[i] = ((key[i - 15] & 127) << 9 | key[i - 14] >> 7) & mask;
            }
        }

        return key;
    }

    /**
     * this function computes multiplicative inverse using euclid's greatest
     * common divisor algorithm. zero and one are self inverse.
     * <p>
     * i.e. x * mulinv(x) == 1 (modulo base)
     */
    private int mulinv(
        int x)
    {
        int t0, t1, q, y;
        
        if (x < 2)
        {
            return x;
        }

        t0 = 1;
        t1 = base / x;
        y  = base % x;

        while (y != 1)
        {
            q = x / y;
            x = x % y;
            t0 = (t0 + (t1 * q)) & mask;
            if (x == 1)
            {
                return t0;
            }
            q = y / x;
            y = y % x;
            t1 = (t1 + (t0 * q)) & mask;
        }

        return (1 - t1) & mask;
    }

    /**
     * return the additive inverse of x.
     * <p>
     * i.e. x + addinv(x) == 0
     */
    int addinv(
        int x)
    {
        return (0 - x) & mask;
    }
    
    /**
     * the function to invert the encryption subkey to the decryption subkey.
     * it also involves the multiplicative inverse and the additive inverse functions.
     */
    private int[] invertkey(
        int[] inkey)
    {
        int     t1, t2, t3, t4;
        int     p = 52;                 /* we work backwards */
        int[]   key = new int[52];
        int     inoff = 0;
    
        t1 = mulinv(inkey[inoff++]);
        t2 = addinv(inkey[inoff++]);
        t3 = addinv(inkey[inoff++]);
        t4 = mulinv(inkey[inoff++]);
        key[--p] = t4;
        key[--p] = t3;
        key[--p] = t2;
        key[--p] = t1;
    
        for (int round = 1; round < 8; round++)
        {
            t1 = inkey[inoff++];
            t2 = inkey[inoff++];
            key[--p] = t2;
            key[--p] = t1;
    
            t1 = mulinv(inkey[inoff++]);
            t2 = addinv(inkey[inoff++]);
            t3 = addinv(inkey[inoff++]);
            t4 = mulinv(inkey[inoff++]);
            key[--p] = t4;
            key[--p] = t2; /* nb: order */
            key[--p] = t3;
            key[--p] = t1;
        }

        t1 = inkey[inoff++];
        t2 = inkey[inoff++];
        key[--p] = t2;
        key[--p] = t1;
    
        t1 = mulinv(inkey[inoff++]);
        t2 = addinv(inkey[inoff++]);
        t3 = addinv(inkey[inoff++]);
        t4 = mulinv(inkey[inoff]);
        key[--p] = t4;
        key[--p] = t3;
        key[--p] = t2;
        key[--p] = t1;

        return key;
    }
    
    private int[] generateworkingkey(
        boolean forencryption,
        byte[]  userkey)
    {
        if (forencryption)
        {
            return expandkey(userkey);
        }
        else
        {
            return invertkey(expandkey(userkey));
        }
    }
}
