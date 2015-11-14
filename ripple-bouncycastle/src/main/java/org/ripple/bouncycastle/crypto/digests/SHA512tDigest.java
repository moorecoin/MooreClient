package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.util.memoable;
import org.ripple.bouncycastle.util.memoableresetexception;

/**
 * fips 180-4 implementation of sha-512/t
 */
public class sha512tdigest
    extends longdigest
{
    private final int digestlength;

    private long  h1t, h2t, h3t, h4t, h5t, h6t, h7t, h8t;

    /**
     * standard constructor
     */
    public sha512tdigest(int bitlength)
    {
        if (bitlength >= 512)
        {
            throw new illegalargumentexception("bitlength cannot be >= 512");
        }

        if (bitlength % 8 != 0)
        {
            throw new illegalargumentexception("bitlength needs to be a multiple of 8");
        }

        if (bitlength == 384)
        {
            throw new illegalargumentexception("bitlength cannot be 384 use sha384 instead");
        }

        this.digestlength = bitlength / 8;

        tivgenerate(digestlength * 8);

        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public sha512tdigest(sha512tdigest t)
    {
        super(t);

        this.digestlength = t.digestlength;

        reset(t);
    }

    public string getalgorithmname()
    {
        return "sha-512/" + integer.tostring(digestlength * 8);
    }

    public int getdigestsize()
    {
        return digestlength;
    }

    public int dofinal(
        byte[]  out,
        int     outoff)
    {
        finish();

        longtobigendian(h1, out, outoff, digestlength);
        longtobigendian(h2, out, outoff + 8, digestlength - 8);
        longtobigendian(h3, out, outoff + 16, digestlength - 16);
        longtobigendian(h4, out, outoff + 24, digestlength - 24);
        longtobigendian(h5, out, outoff + 32, digestlength - 32);
        longtobigendian(h6, out, outoff + 40, digestlength - 40);
        longtobigendian(h7, out, outoff + 48, digestlength - 48);
        longtobigendian(h8, out, outoff + 56, digestlength - 56);

        reset();

        return digestlength;
    }

    /**
     * reset the chaining variables
     */
    public void reset()
    {
        super.reset();

        /*
         * initial hash values use the iv generation algorithm for t.
         */
        h1 = h1t;
        h2 = h2t;
        h3 = h3t;
        h4 = h4t;
        h5 = h5t;
        h6 = h6t;
        h7 = h7t;
        h8 = h8t;
    }

    private void tivgenerate(int bitlength)
    {
        h1 = 0x6a09e667f3bcc908l ^ 0xa5a5a5a5a5a5a5a5l;
        h2 = 0xbb67ae8584caa73bl ^ 0xa5a5a5a5a5a5a5a5l;
        h3 = 0x3c6ef372fe94f82bl ^ 0xa5a5a5a5a5a5a5a5l;
        h4 = 0xa54ff53a5f1d36f1l ^ 0xa5a5a5a5a5a5a5a5l;
        h5 = 0x510e527fade682d1l ^ 0xa5a5a5a5a5a5a5a5l;
        h6 = 0x9b05688c2b3e6c1fl ^ 0xa5a5a5a5a5a5a5a5l;
        h7 = 0x1f83d9abfb41bd6bl ^ 0xa5a5a5a5a5a5a5a5l;
        h8 = 0x5be0cd19137e2179l ^ 0xa5a5a5a5a5a5a5a5l;

        update((byte)0x53);
        update((byte)0x48);
        update((byte)0x41);
        update((byte)0x2d);
        update((byte)0x35);
        update((byte)0x31);
        update((byte)0x32);
        update((byte)0x2f);

        if (bitlength > 100)
        {
            update((byte)(bitlength / 100 + 0x30));
            bitlength = bitlength % 100;
            update((byte)(bitlength / 10 + 0x30));
            bitlength = bitlength % 10;
            update((byte)(bitlength + 0x30));
        }
        else if (bitlength > 10)
        {
            update((byte)(bitlength / 10 + 0x30));
            bitlength = bitlength % 10;
            update((byte)(bitlength + 0x30));
        }
        else
        {
            update((byte)(bitlength + 0x30));
        }

        finish();

        h1t = h1;
        h2t = h2;
        h3t = h3;
        h4t = h4;
        h5t = h5;
        h6t = h6;
        h7t = h7;
        h8t = h8;
    }

    private static void longtobigendian(long n, byte[] bs, int off, int max)
    {
        if (max > 0)
        {
            inttobigendian((int)(n >>> 32), bs, off, max);

            if (max > 4)
            {
                inttobigendian((int)(n & 0xffffffffl), bs, off + 4, max - 4);
            }
        }
    }

    private static void inttobigendian(int n, byte[] bs, int off, int max)
    {
        int num = math.min(4, max);
        while (--num >= 0)
        {
            int shift = 8 * (3 - num);
            bs[off + num] = (byte)(n >>> shift);
        }
    }

    public memoable copy()
    {
        return new sha512tdigest(this);
    }

    public void reset(memoable other)
    {
        sha512tdigest t = (sha512tdigest)other;

        if (this.digestlength != t.digestlength)
        {
            throw new memoableresetexception("digestlength inappropriate in other");
        }

        super.copyin(t);

        this.h1t = t.h1t;
        this.h2t = t.h2t;
        this.h3t = t.h3t;
        this.h4t = t.h4t;
        this.h5t = t.h5t;
        this.h6t = t.h6t;
        this.h7t = t.h7t;
        this.h8t = t.h8t;
    }
}
