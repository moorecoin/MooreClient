package org.ripple.bouncycastle.crypto.digests;


import org.ripple.bouncycastle.util.memoable;

/**
 * implementation of md4 as rfc 1320 by r. rivest, mit laboratory for
 * computer science and rsa data security, inc.
 * <p>
 * <b>note</b>: this algorithm is only included for backwards compatability
 * with legacy applications, it's not secure, don't use it for anything new!
 */
public class md4digest
    extends generaldigest
{
    private static final int    digest_length = 16;

    private int     h1, h2, h3, h4;         // iv's

    private int[]   x = new int[16];
    private int     xoff;

    /**
     * standard constructor
     */
    public md4digest()
    {
        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public md4digest(md4digest t)
    {
        super(t);

        copyin(t);
    }

    private void copyin(md4digest t)
    {
        super.copyin(t);

        h1 = t.h1;
        h2 = t.h2;
        h3 = t.h3;
        h4 = t.h4;

        system.arraycopy(t.x, 0, x, 0, t.x.length);
        xoff = t.xoff;
    }

    public string getalgorithmname()
    {
        return "md4";
    }

    public int getdigestsize()
    {
        return digest_length;
    }

    protected void processword(
        byte[]  in,
        int     inoff)
    {
        x[xoff++] = (in[inoff] & 0xff) | ((in[inoff + 1] & 0xff) << 8)
            | ((in[inoff + 2] & 0xff) << 16) | ((in[inoff + 3] & 0xff) << 24); 

        if (xoff == 16)
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

        x[14] = (int)(bitlength & 0xffffffff);
        x[15] = (int)(bitlength >>> 32);
    }

    private void unpackword(
        int     word,
        byte[]  out,
        int     outoff)
    {
        out[outoff]     = (byte)word;
        out[outoff + 1] = (byte)(word >>> 8);
        out[outoff + 2] = (byte)(word >>> 16);
        out[outoff + 3] = (byte)(word >>> 24);
    }

    public int dofinal(
        byte[]  out,
        int     outoff)
    {
        finish();

        unpackword(h1, out, outoff);
        unpackword(h2, out, outoff + 4);
        unpackword(h3, out, outoff + 8);
        unpackword(h4, out, outoff + 12);

        reset();

        return digest_length;
    }

    /**
     * reset the chaining variables to the iv values.
     */
    public void reset()
    {
        super.reset();

        h1 = 0x67452301;
        h2 = 0xefcdab89;
        h3 = 0x98badcfe;
        h4 = 0x10325476;

        xoff = 0;

        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }
    }

    //
    // round 1 left rotates
    //
    private static final int s11 = 3;
    private static final int s12 = 7;
    private static final int s13 = 11;
    private static final int s14 = 19;

    //
    // round 2 left rotates
    //
    private static final int s21 = 3;
    private static final int s22 = 5;
    private static final int s23 = 9;
    private static final int s24 = 13;

    //
    // round 3 left rotates
    //
    private static final int s31 = 3;
    private static final int s32 = 9;
    private static final int s33 = 11;
    private static final int s34 = 15;

    /*
     * rotate int x left n bits.
     */
    private int rotateleft(
        int x,
        int n)
    {
        return (x << n) | (x >>> (32 - n));
    }

    /*
     * f, g, h and i are the basic md4 functions.
     */
    private int f(
        int u,
        int v,
        int w)
    {
        return (u & v) | (~u & w);
    }

    private int g(
        int u,
        int v,
        int w)
    {
        return (u & v) | (u & w) | (v & w);
    }

    private int h(
        int u,
        int v,
        int w)
    {
        return u ^ v ^ w;
    }

    protected void processblock()
    {
        int a = h1;
        int b = h2;
        int c = h3;
        int d = h4;

        //
        // round 1 - f cycle, 16 times.
        //
        a = rotateleft(a + f(b, c, d) + x[ 0], s11);
        d = rotateleft(d + f(a, b, c) + x[ 1], s12);
        c = rotateleft(c + f(d, a, b) + x[ 2], s13);
        b = rotateleft(b + f(c, d, a) + x[ 3], s14);
        a = rotateleft(a + f(b, c, d) + x[ 4], s11);
        d = rotateleft(d + f(a, b, c) + x[ 5], s12);
        c = rotateleft(c + f(d, a, b) + x[ 6], s13);
        b = rotateleft(b + f(c, d, a) + x[ 7], s14);
        a = rotateleft(a + f(b, c, d) + x[ 8], s11);
        d = rotateleft(d + f(a, b, c) + x[ 9], s12);
        c = rotateleft(c + f(d, a, b) + x[10], s13);
        b = rotateleft(b + f(c, d, a) + x[11], s14);
        a = rotateleft(a + f(b, c, d) + x[12], s11);
        d = rotateleft(d + f(a, b, c) + x[13], s12);
        c = rotateleft(c + f(d, a, b) + x[14], s13);
        b = rotateleft(b + f(c, d, a) + x[15], s14);

        //
        // round 2 - g cycle, 16 times.
        //
        a = rotateleft(a + g(b, c, d) + x[ 0] + 0x5a827999, s21);
        d = rotateleft(d + g(a, b, c) + x[ 4] + 0x5a827999, s22);
        c = rotateleft(c + g(d, a, b) + x[ 8] + 0x5a827999, s23);
        b = rotateleft(b + g(c, d, a) + x[12] + 0x5a827999, s24);
        a = rotateleft(a + g(b, c, d) + x[ 1] + 0x5a827999, s21);
        d = rotateleft(d + g(a, b, c) + x[ 5] + 0x5a827999, s22);
        c = rotateleft(c + g(d, a, b) + x[ 9] + 0x5a827999, s23);
        b = rotateleft(b + g(c, d, a) + x[13] + 0x5a827999, s24);
        a = rotateleft(a + g(b, c, d) + x[ 2] + 0x5a827999, s21);
        d = rotateleft(d + g(a, b, c) + x[ 6] + 0x5a827999, s22);
        c = rotateleft(c + g(d, a, b) + x[10] + 0x5a827999, s23);
        b = rotateleft(b + g(c, d, a) + x[14] + 0x5a827999, s24);
        a = rotateleft(a + g(b, c, d) + x[ 3] + 0x5a827999, s21);
        d = rotateleft(d + g(a, b, c) + x[ 7] + 0x5a827999, s22);
        c = rotateleft(c + g(d, a, b) + x[11] + 0x5a827999, s23);
        b = rotateleft(b + g(c, d, a) + x[15] + 0x5a827999, s24);

        //
        // round 3 - h cycle, 16 times.
        //
        a = rotateleft(a + h(b, c, d) + x[ 0] + 0x6ed9eba1, s31);
        d = rotateleft(d + h(a, b, c) + x[ 8] + 0x6ed9eba1, s32);
        c = rotateleft(c + h(d, a, b) + x[ 4] + 0x6ed9eba1, s33);
        b = rotateleft(b + h(c, d, a) + x[12] + 0x6ed9eba1, s34);
        a = rotateleft(a + h(b, c, d) + x[ 2] + 0x6ed9eba1, s31);
        d = rotateleft(d + h(a, b, c) + x[10] + 0x6ed9eba1, s32);
        c = rotateleft(c + h(d, a, b) + x[ 6] + 0x6ed9eba1, s33);
        b = rotateleft(b + h(c, d, a) + x[14] + 0x6ed9eba1, s34);
        a = rotateleft(a + h(b, c, d) + x[ 1] + 0x6ed9eba1, s31);
        d = rotateleft(d + h(a, b, c) + x[ 9] + 0x6ed9eba1, s32);
        c = rotateleft(c + h(d, a, b) + x[ 5] + 0x6ed9eba1, s33);
        b = rotateleft(b + h(c, d, a) + x[13] + 0x6ed9eba1, s34);
        a = rotateleft(a + h(b, c, d) + x[ 3] + 0x6ed9eba1, s31);
        d = rotateleft(d + h(a, b, c) + x[11] + 0x6ed9eba1, s32);
        c = rotateleft(c + h(d, a, b) + x[ 7] + 0x6ed9eba1, s33);
        b = rotateleft(b + h(c, d, a) + x[15] + 0x6ed9eba1, s34);

        h1 += a;
        h2 += b;
        h3 += c;
        h4 += d;

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
        return new md4digest(this);
    }

    public void reset(memoable other)
    {
        md4digest d = (md4digest)other;

        copyin(d);
    }
}
