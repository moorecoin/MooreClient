package org.ripple.bouncycastle.crypto.digests;


import org.ripple.bouncycastle.util.memoable;

/**
 * implementation of md5 as outlined in "handbook of applied cryptography", pages 346 - 347.
 */
public class md5digest
    extends generaldigest
{
    private static final int    digest_length = 16;

    private int     h1, h2, h3, h4;         // iv's

    private int[]   x = new int[16];
    private int     xoff;

    /**
     * standard constructor
     */
    public md5digest()
    {
        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public md5digest(md5digest t)
    {
        super(t);

        copyin(t);
    }

    private void copyin(md5digest t)
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
        return "md5";
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
    private static final int s11 = 7;
    private static final int s12 = 12;
    private static final int s13 = 17;
    private static final int s14 = 22;

    //
    // round 2 left rotates
    //
    private static final int s21 = 5;
    private static final int s22 = 9;
    private static final int s23 = 14;
    private static final int s24 = 20;

    //
    // round 3 left rotates
    //
    private static final int s31 = 4;
    private static final int s32 = 11;
    private static final int s33 = 16;
    private static final int s34 = 23;

    //
    // round 4 left rotates
    //
    private static final int s41 = 6;
    private static final int s42 = 10;
    private static final int s43 = 15;
    private static final int s44 = 21;

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
     * f, g, h and i are the basic md5 functions.
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
        return (u & w) | (v & ~w);
    }

    private int h(
        int u,
        int v,
        int w)
    {
        return u ^ v ^ w;
    }

    private int k(
        int u,
        int v,
        int w)
    {
        return v ^ (u | ~w);
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
        a = rotateleft(a + f(b, c, d) + x[ 0] + 0xd76aa478, s11) + b;
        d = rotateleft(d + f(a, b, c) + x[ 1] + 0xe8c7b756, s12) + a;
        c = rotateleft(c + f(d, a, b) + x[ 2] + 0x242070db, s13) + d;
        b = rotateleft(b + f(c, d, a) + x[ 3] + 0xc1bdceee, s14) + c;
        a = rotateleft(a + f(b, c, d) + x[ 4] + 0xf57c0faf, s11) + b;
        d = rotateleft(d + f(a, b, c) + x[ 5] + 0x4787c62a, s12) + a;
        c = rotateleft(c + f(d, a, b) + x[ 6] + 0xa8304613, s13) + d;
        b = rotateleft(b + f(c, d, a) + x[ 7] + 0xfd469501, s14) + c;
        a = rotateleft(a + f(b, c, d) + x[ 8] + 0x698098d8, s11) + b;
        d = rotateleft(d + f(a, b, c) + x[ 9] + 0x8b44f7af, s12) + a;
        c = rotateleft(c + f(d, a, b) + x[10] + 0xffff5bb1, s13) + d;
        b = rotateleft(b + f(c, d, a) + x[11] + 0x895cd7be, s14) + c;
        a = rotateleft(a + f(b, c, d) + x[12] + 0x6b901122, s11) + b;
        d = rotateleft(d + f(a, b, c) + x[13] + 0xfd987193, s12) + a;
        c = rotateleft(c + f(d, a, b) + x[14] + 0xa679438e, s13) + d;
        b = rotateleft(b + f(c, d, a) + x[15] + 0x49b40821, s14) + c;

        //
        // round 2 - g cycle, 16 times.
        //
        a = rotateleft(a + g(b, c, d) + x[ 1] + 0xf61e2562, s21) + b;
        d = rotateleft(d + g(a, b, c) + x[ 6] + 0xc040b340, s22) + a;
        c = rotateleft(c + g(d, a, b) + x[11] + 0x265e5a51, s23) + d;
        b = rotateleft(b + g(c, d, a) + x[ 0] + 0xe9b6c7aa, s24) + c;
        a = rotateleft(a + g(b, c, d) + x[ 5] + 0xd62f105d, s21) + b;
        d = rotateleft(d + g(a, b, c) + x[10] + 0x02441453, s22) + a;
        c = rotateleft(c + g(d, a, b) + x[15] + 0xd8a1e681, s23) + d;
        b = rotateleft(b + g(c, d, a) + x[ 4] + 0xe7d3fbc8, s24) + c;
        a = rotateleft(a + g(b, c, d) + x[ 9] + 0x21e1cde6, s21) + b;
        d = rotateleft(d + g(a, b, c) + x[14] + 0xc33707d6, s22) + a;
        c = rotateleft(c + g(d, a, b) + x[ 3] + 0xf4d50d87, s23) + d;
        b = rotateleft(b + g(c, d, a) + x[ 8] + 0x455a14ed, s24) + c;
        a = rotateleft(a + g(b, c, d) + x[13] + 0xa9e3e905, s21) + b;
        d = rotateleft(d + g(a, b, c) + x[ 2] + 0xfcefa3f8, s22) + a;
        c = rotateleft(c + g(d, a, b) + x[ 7] + 0x676f02d9, s23) + d;
        b = rotateleft(b + g(c, d, a) + x[12] + 0x8d2a4c8a, s24) + c;

        //
        // round 3 - h cycle, 16 times.
        //
        a = rotateleft(a + h(b, c, d) + x[ 5] + 0xfffa3942, s31) + b;
        d = rotateleft(d + h(a, b, c) + x[ 8] + 0x8771f681, s32) + a;
        c = rotateleft(c + h(d, a, b) + x[11] + 0x6d9d6122, s33) + d;
        b = rotateleft(b + h(c, d, a) + x[14] + 0xfde5380c, s34) + c;
        a = rotateleft(a + h(b, c, d) + x[ 1] + 0xa4beea44, s31) + b;
        d = rotateleft(d + h(a, b, c) + x[ 4] + 0x4bdecfa9, s32) + a;
        c = rotateleft(c + h(d, a, b) + x[ 7] + 0xf6bb4b60, s33) + d;
        b = rotateleft(b + h(c, d, a) + x[10] + 0xbebfbc70, s34) + c;
        a = rotateleft(a + h(b, c, d) + x[13] + 0x289b7ec6, s31) + b;
        d = rotateleft(d + h(a, b, c) + x[ 0] + 0xeaa127fa, s32) + a;
        c = rotateleft(c + h(d, a, b) + x[ 3] + 0xd4ef3085, s33) + d;
        b = rotateleft(b + h(c, d, a) + x[ 6] + 0x04881d05, s34) + c;
        a = rotateleft(a + h(b, c, d) + x[ 9] + 0xd9d4d039, s31) + b;
        d = rotateleft(d + h(a, b, c) + x[12] + 0xe6db99e5, s32) + a;
        c = rotateleft(c + h(d, a, b) + x[15] + 0x1fa27cf8, s33) + d;
        b = rotateleft(b + h(c, d, a) + x[ 2] + 0xc4ac5665, s34) + c;

        //
        // round 4 - k cycle, 16 times.
        //
        a = rotateleft(a + k(b, c, d) + x[ 0] + 0xf4292244, s41) + b;
        d = rotateleft(d + k(a, b, c) + x[ 7] + 0x432aff97, s42) + a;
        c = rotateleft(c + k(d, a, b) + x[14] + 0xab9423a7, s43) + d;
        b = rotateleft(b + k(c, d, a) + x[ 5] + 0xfc93a039, s44) + c;
        a = rotateleft(a + k(b, c, d) + x[12] + 0x655b59c3, s41) + b;
        d = rotateleft(d + k(a, b, c) + x[ 3] + 0x8f0ccc92, s42) + a;
        c = rotateleft(c + k(d, a, b) + x[10] + 0xffeff47d, s43) + d;
        b = rotateleft(b + k(c, d, a) + x[ 1] + 0x85845dd1, s44) + c;
        a = rotateleft(a + k(b, c, d) + x[ 8] + 0x6fa87e4f, s41) + b;
        d = rotateleft(d + k(a, b, c) + x[15] + 0xfe2ce6e0, s42) + a;
        c = rotateleft(c + k(d, a, b) + x[ 6] + 0xa3014314, s43) + d;
        b = rotateleft(b + k(c, d, a) + x[13] + 0x4e0811a1, s44) + c;
        a = rotateleft(a + k(b, c, d) + x[ 4] + 0xf7537e82, s41) + b;
        d = rotateleft(d + k(a, b, c) + x[11] + 0xbd3af235, s42) + a;
        c = rotateleft(c + k(d, a, b) + x[ 2] + 0x2ad7d2bb, s43) + d;
        b = rotateleft(b + k(c, d, a) + x[ 9] + 0xeb86d391, s44) + c;

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
        return new md5digest(this);
    }

    public void reset(memoable other)
    {
        md5digest d = (md5digest)other;

        copyin(d);
    }
}
