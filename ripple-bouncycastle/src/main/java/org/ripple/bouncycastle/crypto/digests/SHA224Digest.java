package org.ripple.bouncycastle.crypto.digests;


import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.memoable;


/**
 * sha-224 as described in rfc 3874
 * <pre>
 *         block  word  digest
 * sha-1   512    32    160
 * sha-224 512    32    224
 * sha-256 512    32    256
 * sha-384 1024   64    384
 * sha-512 1024   64    512
 * </pre>
 */
public class sha224digest
    extends generaldigest
{
    private static final int    digest_length = 28;

    private int     h1, h2, h3, h4, h5, h6, h7, h8;

    private int[]   x = new int[64];
    private int     xoff;

    /**
     * standard constructor
     */
    public sha224digest()
    {
        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public sha224digest(sha224digest t)
    {
        super(t);

        docopy(t);
    }

    private void docopy(sha224digest t)
    {
        super.copyin(t);

        h1 = t.h1;
        h2 = t.h2;
        h3 = t.h3;
        h4 = t.h4;
        h5 = t.h5;
        h6 = t.h6;
        h7 = t.h7;
        h8 = t.h8;

        system.arraycopy(t.x, 0, x, 0, t.x.length);
        xoff = t.xoff;
    }

    public string getalgorithmname()
    {
        return "sha-224";
    }

    public int getdigestsize()
    {
        return digest_length;
    }

    protected void processword(
        byte[]  in,
        int     inoff)
    {
        // note: inlined for performance
//        x[xoff] = pack.bigendiantoint(in, inoff);
        int n = in[  inoff] << 24;
        n |= (in[++inoff] & 0xff) << 16;
        n |= (in[++inoff] & 0xff) << 8;
        n |= (in[++inoff] & 0xff);
        x[xoff] = n;

        if (++xoff == 16)
        {
            processblock();
        }
    }

    protected void processlength(
        long    bitlength)
    {
        if (xoff > 14)
        {
            processblock();
        }

        x[14] = (int)(bitlength >>> 32);
        x[15] = (int)(bitlength & 0xffffffff);
    }

    public int dofinal(
        byte[]  out,
        int     outoff)
    {
        finish();

        pack.inttobigendian(h1, out, outoff);
        pack.inttobigendian(h2, out, outoff + 4);
        pack.inttobigendian(h3, out, outoff + 8);
        pack.inttobigendian(h4, out, outoff + 12);
        pack.inttobigendian(h5, out, outoff + 16);
        pack.inttobigendian(h6, out, outoff + 20);
        pack.inttobigendian(h7, out, outoff + 24);

        reset();

        return digest_length;
    }

    /**
     * reset the chaining variables
     */
    public void reset()
    {
        super.reset();

        /* sha-224 initial hash value
         */

        h1 = 0xc1059ed8;
        h2 = 0x367cd507;
        h3 = 0x3070dd17;
        h4 = 0xf70e5939;
        h5 = 0xffc00b31;
        h6 = 0x68581511;
        h7 = 0x64f98fa7;
        h8 = 0xbefa4fa4;

        xoff = 0;
        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }
    }

    protected void processblock()
    {
        //
        // expand 16 word block into 64 word blocks.
        //
        for (int t = 16; t <= 63; t++)
        {
            x[t] = theta1(x[t - 2]) + x[t - 7] + theta0(x[t - 15]) + x[t - 16];
        }

        //
        // set up working variables.
        //
        int     a = h1;
        int     b = h2;
        int     c = h3;
        int     d = h4;
        int     e = h5;
        int     f = h6;
        int     g = h7;
        int     h = h8;


        int t = 0;     
        for(int i = 0; i < 8; i ++)
        {
            // t = 8 * i
            h += sum1(e) + ch(e, f, g) + k[t] + x[t];
            d += h;
            h += sum0(a) + maj(a, b, c);
            ++t;

            // t = 8 * i + 1
            g += sum1(d) + ch(d, e, f) + k[t] + x[t];
            c += g;
            g += sum0(h) + maj(h, a, b);
            ++t;

            // t = 8 * i + 2
            f += sum1(c) + ch(c, d, e) + k[t] + x[t];
            b += f;
            f += sum0(g) + maj(g, h, a);
            ++t;

            // t = 8 * i + 3
            e += sum1(b) + ch(b, c, d) + k[t] + x[t];
            a += e;
            e += sum0(f) + maj(f, g, h);
            ++t;

            // t = 8 * i + 4
            d += sum1(a) + ch(a, b, c) + k[t] + x[t];
            h += d;
            d += sum0(e) + maj(e, f, g);
            ++t;

            // t = 8 * i + 5
            c += sum1(h) + ch(h, a, b) + k[t] + x[t];
            g += c;
            c += sum0(d) + maj(d, e, f);
            ++t;

            // t = 8 * i + 6
            b += sum1(g) + ch(g, h, a) + k[t] + x[t];
            f += b;
            b += sum0(c) + maj(c, d, e);
            ++t;

            // t = 8 * i + 7
            a += sum1(f) + ch(f, g, h) + k[t] + x[t];
            e += a;
            a += sum0(b) + maj(b, c, d);
            ++t;
        }

        h1 += a;
        h2 += b;
        h3 += c;
        h4 += d;
        h5 += e;
        h6 += f;
        h7 += g;
        h8 += h;

        //
        // reset the offset and clean out the word buffer.
        //
        xoff = 0;
        for (int i = 0; i < 16; i++)
        {
            x[i] = 0;
        }
    }

    /* sha-224 functions */
    private int ch(
        int    x,
        int    y,
        int    z)
    {
        return ((x & y) ^ ((~x) & z));
    }

    private int maj(
        int    x,
        int    y,
        int    z)
    {
        return ((x & y) ^ (x & z) ^ (y & z));
    }

    private int sum0(
        int    x)
    {
        return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^ ((x >>> 22) | (x << 10));
    }

    private int sum1(
        int    x)
    {
        return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^ ((x >>> 25) | (x << 7));
    }

    private int theta0(
        int    x)
    {
        return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    private int theta1(
        int    x)
    {
        return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }

    /* sha-224 constants
     * (represent the first 32 bits of the fractional parts of the
     * cube roots of the first sixty-four prime numbers)
     */
    static final int k[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    public memoable copy()
    {
        return new sha224digest(this);
    }

    public void reset(memoable other)
    {
        sha224digest d = (sha224digest)other;

        docopy(d);
    }
}

