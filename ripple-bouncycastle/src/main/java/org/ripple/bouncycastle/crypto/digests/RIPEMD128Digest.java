package org.ripple.bouncycastle.crypto.digests;


import org.ripple.bouncycastle.util.memoable;

/**
 * implementation of ripemd128
 */
public class ripemd128digest
    extends generaldigest
{
    private static final int digest_length = 16;

    private int h0, h1, h2, h3; // iv's

    private int[] x = new int[16];
    private int xoff;

    /**
     * standard constructor
     */
    public ripemd128digest()
    {
        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public ripemd128digest(ripemd128digest t)
    {
        super(t);

        copyin(t);
    }

    private void copyin(ripemd128digest t)
    {
        super.copyin(t);

        h0 = t.h0;
        h1 = t.h1;
        h2 = t.h2;
        h3 = t.h3;

        system.arraycopy(t.x, 0, x, 0, t.x.length);
        xoff = t.xoff;
    }

    public string getalgorithmname()
    {
        return "ripemd128";
    }

    public int getdigestsize()
    {
        return digest_length;
    }

    protected void processword(
        byte[] in,
        int inoff)
    {
        x[xoff++] = (in[inoff] & 0xff) | ((in[inoff + 1] & 0xff) << 8)
            | ((in[inoff + 2] & 0xff) << 16) | ((in[inoff + 3] & 0xff) << 24); 

        if (xoff == 16)
        {
            processblock();
        }
    }

    protected void processlength(
        long bitlength)
    {
        if (xoff > 14)
        {
        processblock();
        }

        x[14] = (int)(bitlength & 0xffffffff);
        x[15] = (int)(bitlength >>> 32);
    }

    private void unpackword(
        int word,
        byte[] out,
        int outoff)
    {
        out[outoff]     = (byte)word;
        out[outoff + 1] = (byte)(word >>> 8);
        out[outoff + 2] = (byte)(word >>> 16);
        out[outoff + 3] = (byte)(word >>> 24);
    }

    public int dofinal(
        byte[] out,
        int outoff)
    {
        finish();

        unpackword(h0, out, outoff);
        unpackword(h1, out, outoff + 4);
        unpackword(h2, out, outoff + 8);
        unpackword(h3, out, outoff + 12);

        reset();

        return digest_length;
    }

    /**
    * reset the chaining variables to the iv values.
    */
    public void reset()
    {
        super.reset();

        h0 = 0x67452301;
        h1 = 0xefcdab89;
        h2 = 0x98badcfe;
        h3 = 0x10325476;

        xoff = 0;

        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }
    }

    /*
     * rotate int x left n bits.
     */
    private int rl(
        int x,
        int n)
    {
        return (x << n) | (x >>> (32 - n));
    }

    /*
     * f1,f2,f3,f4 are the basic ripemd128 functions.
     */

    /*
     * f
     */
    private int f1(
        int x,
        int y,
        int z)
    {
        return x ^ y ^ z;
    }

    /*
     * g
     */
    private int f2(
        int x,
        int y,
        int z)
    {
        return (x & y) | (~x & z);
    }

    /*
     * h
     */
    private int f3(
        int x,
        int y,
        int z)
    {
        return (x | ~y) ^ z;
    }

    /*
     * i
     */
    private int f4(
        int x,
        int y,
        int z)
    {
        return (x & z) | (y & ~z);
    }

    private int f1(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return rl(a + f1(b, c, d) + x, s);
    }

    private int f2(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return rl(a + f2(b, c, d) + x + 0x5a827999, s);
    }

    private int f3(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return rl(a + f3(b, c, d) + x + 0x6ed9eba1, s);
    }

    private int f4(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return rl(a + f4(b, c, d) + x + 0x8f1bbcdc, s);
    }

    private int ff1(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
        return rl(a + f1(b, c, d) + x, s);
    }

    private int ff2(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
      return rl(a + f2(b, c, d) + x + 0x6d703ef3, s);
    }

    private int ff3(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
      return rl(a + f3(b, c, d) + x + 0x5c4dd124, s);
    }

    private int ff4(
        int a,
        int b,
        int c,
        int d,
        int x,
        int s)
    {
      return rl(a + f4(b, c, d) + x + 0x50a28be6, s);
    }

    protected void processblock()
    {
        int a, aa;
        int b, bb;
        int c, cc;
        int d, dd;

        a = aa = h0;
        b = bb = h1;
        c = cc = h2;
        d = dd = h3;

        //
        // round 1
        //
        a = f1(a, b, c, d, x[ 0], 11);
        d = f1(d, a, b, c, x[ 1], 14);
        c = f1(c, d, a, b, x[ 2], 15);
        b = f1(b, c, d, a, x[ 3], 12);
        a = f1(a, b, c, d, x[ 4],  5);
        d = f1(d, a, b, c, x[ 5],  8);
        c = f1(c, d, a, b, x[ 6],  7);
        b = f1(b, c, d, a, x[ 7],  9);
        a = f1(a, b, c, d, x[ 8], 11);
        d = f1(d, a, b, c, x[ 9], 13);
        c = f1(c, d, a, b, x[10], 14);
        b = f1(b, c, d, a, x[11], 15);
        a = f1(a, b, c, d, x[12],  6);
        d = f1(d, a, b, c, x[13],  7);
        c = f1(c, d, a, b, x[14],  9);
        b = f1(b, c, d, a, x[15],  8);

        //
        // round 2
        //
        a = f2(a, b, c, d, x[ 7],  7);
        d = f2(d, a, b, c, x[ 4],  6);
        c = f2(c, d, a, b, x[13],  8);
        b = f2(b, c, d, a, x[ 1], 13);
        a = f2(a, b, c, d, x[10], 11);
        d = f2(d, a, b, c, x[ 6],  9);
        c = f2(c, d, a, b, x[15],  7);
        b = f2(b, c, d, a, x[ 3], 15);
        a = f2(a, b, c, d, x[12],  7);
        d = f2(d, a, b, c, x[ 0], 12);
        c = f2(c, d, a, b, x[ 9], 15);
        b = f2(b, c, d, a, x[ 5],  9);
        a = f2(a, b, c, d, x[ 2], 11);
        d = f2(d, a, b, c, x[14],  7);
        c = f2(c, d, a, b, x[11], 13);
        b = f2(b, c, d, a, x[ 8], 12);

        //
        // round 3
        //
        a = f3(a, b, c, d, x[ 3], 11);
        d = f3(d, a, b, c, x[10], 13);
        c = f3(c, d, a, b, x[14],  6);
        b = f3(b, c, d, a, x[ 4],  7);
        a = f3(a, b, c, d, x[ 9], 14);
        d = f3(d, a, b, c, x[15],  9);
        c = f3(c, d, a, b, x[ 8], 13);
        b = f3(b, c, d, a, x[ 1], 15);
        a = f3(a, b, c, d, x[ 2], 14);
        d = f3(d, a, b, c, x[ 7],  8);
        c = f3(c, d, a, b, x[ 0], 13);
        b = f3(b, c, d, a, x[ 6],  6);
        a = f3(a, b, c, d, x[13],  5);
        d = f3(d, a, b, c, x[11], 12);
        c = f3(c, d, a, b, x[ 5],  7);
        b = f3(b, c, d, a, x[12],  5);

        //
        // round 4
        //
        a = f4(a, b, c, d, x[ 1], 11);
        d = f4(d, a, b, c, x[ 9], 12);
        c = f4(c, d, a, b, x[11], 14);
        b = f4(b, c, d, a, x[10], 15);
        a = f4(a, b, c, d, x[ 0], 14);
        d = f4(d, a, b, c, x[ 8], 15);
        c = f4(c, d, a, b, x[12],  9);
        b = f4(b, c, d, a, x[ 4],  8);
        a = f4(a, b, c, d, x[13],  9);
        d = f4(d, a, b, c, x[ 3], 14);
        c = f4(c, d, a, b, x[ 7],  5);
        b = f4(b, c, d, a, x[15],  6);
        a = f4(a, b, c, d, x[14],  8);
        d = f4(d, a, b, c, x[ 5],  6);
        c = f4(c, d, a, b, x[ 6],  5);
        b = f4(b, c, d, a, x[ 2], 12);

        //
        // parallel round 1
        //
        aa = ff4(aa, bb, cc, dd, x[ 5],  8);
        dd = ff4(dd, aa, bb, cc, x[14],  9);
        cc = ff4(cc, dd, aa, bb, x[ 7],  9);
        bb = ff4(bb, cc, dd, aa, x[ 0], 11);
        aa = ff4(aa, bb, cc, dd, x[ 9], 13);
        dd = ff4(dd, aa, bb, cc, x[ 2], 15);
        cc = ff4(cc, dd, aa, bb, x[11], 15);
        bb = ff4(bb, cc, dd, aa, x[ 4],  5);
        aa = ff4(aa, bb, cc, dd, x[13],  7);
        dd = ff4(dd, aa, bb, cc, x[ 6],  7);
        cc = ff4(cc, dd, aa, bb, x[15],  8);
        bb = ff4(bb, cc, dd, aa, x[ 8], 11);
        aa = ff4(aa, bb, cc, dd, x[ 1], 14);
        dd = ff4(dd, aa, bb, cc, x[10], 14);
        cc = ff4(cc, dd, aa, bb, x[ 3], 12);
        bb = ff4(bb, cc, dd, aa, x[12],  6);

        //
        // parallel round 2
        //
        aa = ff3(aa, bb, cc, dd, x[ 6],  9);
        dd = ff3(dd, aa, bb, cc, x[11], 13);
        cc = ff3(cc, dd, aa, bb, x[ 3], 15);
        bb = ff3(bb, cc, dd, aa, x[ 7],  7);
        aa = ff3(aa, bb, cc, dd, x[ 0], 12);
        dd = ff3(dd, aa, bb, cc, x[13],  8);
        cc = ff3(cc, dd, aa, bb, x[ 5],  9);
        bb = ff3(bb, cc, dd, aa, x[10], 11);
        aa = ff3(aa, bb, cc, dd, x[14],  7);
        dd = ff3(dd, aa, bb, cc, x[15],  7);
        cc = ff3(cc, dd, aa, bb, x[ 8], 12);
        bb = ff3(bb, cc, dd, aa, x[12],  7);
        aa = ff3(aa, bb, cc, dd, x[ 4],  6);
        dd = ff3(dd, aa, bb, cc, x[ 9], 15);
        cc = ff3(cc, dd, aa, bb, x[ 1], 13);
        bb = ff3(bb, cc, dd, aa, x[ 2], 11);

        //
        // parallel round 3
        //
        aa = ff2(aa, bb, cc, dd, x[15],  9);
        dd = ff2(dd, aa, bb, cc, x[ 5],  7);
        cc = ff2(cc, dd, aa, bb, x[ 1], 15);
        bb = ff2(bb, cc, dd, aa, x[ 3], 11);
        aa = ff2(aa, bb, cc, dd, x[ 7],  8);
        dd = ff2(dd, aa, bb, cc, x[14],  6);
        cc = ff2(cc, dd, aa, bb, x[ 6],  6);
        bb = ff2(bb, cc, dd, aa, x[ 9], 14);
        aa = ff2(aa, bb, cc, dd, x[11], 12);
        dd = ff2(dd, aa, bb, cc, x[ 8], 13);
        cc = ff2(cc, dd, aa, bb, x[12],  5);
        bb = ff2(bb, cc, dd, aa, x[ 2], 14);
        aa = ff2(aa, bb, cc, dd, x[10], 13);
        dd = ff2(dd, aa, bb, cc, x[ 0], 13);
        cc = ff2(cc, dd, aa, bb, x[ 4],  7);
        bb = ff2(bb, cc, dd, aa, x[13],  5);

        //
        // parallel round 4
        //
        aa = ff1(aa, bb, cc, dd, x[ 8], 15);
        dd = ff1(dd, aa, bb, cc, x[ 6],  5);
        cc = ff1(cc, dd, aa, bb, x[ 4],  8);
        bb = ff1(bb, cc, dd, aa, x[ 1], 11);
        aa = ff1(aa, bb, cc, dd, x[ 3], 14);
        dd = ff1(dd, aa, bb, cc, x[11], 14);
        cc = ff1(cc, dd, aa, bb, x[15],  6);
        bb = ff1(bb, cc, dd, aa, x[ 0], 14);
        aa = ff1(aa, bb, cc, dd, x[ 5],  6);
        dd = ff1(dd, aa, bb, cc, x[12],  9);
        cc = ff1(cc, dd, aa, bb, x[ 2], 12);
        bb = ff1(bb, cc, dd, aa, x[13],  9);
        aa = ff1(aa, bb, cc, dd, x[ 9], 12);
        dd = ff1(dd, aa, bb, cc, x[ 7],  5);
        cc = ff1(cc, dd, aa, bb, x[10], 15);
        bb = ff1(bb, cc, dd, aa, x[14],  8);

        dd += c + h1;               // final result for h0

        //
        // combine the results
        //
        h1 = h2 + d + aa;
        h2 = h3 + a + bb;
        h3 = h0 + b + cc;
        h0 = dd;

        //
        // reset the offset and clean out the word buffer.
        //
        xoff = 0;
        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }
    }

    public memoable copy()
    {
        return new ripemd128digest(this);
    }

    public void reset(memoable other)
    {
        ripemd128digest d = (ripemd128digest)other;

        copyin(d);
    }
}
