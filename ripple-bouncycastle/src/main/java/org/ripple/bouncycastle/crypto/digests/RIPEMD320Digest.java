package org.ripple.bouncycastle.crypto.digests;


import org.ripple.bouncycastle.util.memoable;

/**
 * implementation of ripemd 320.
 * <p>
 * <b>note:</b> this implementation offers the same level of security
 * as ripemd 160.
 */
public class ripemd320digest
    extends generaldigest
{
    private static final int digest_length = 40;

    private int h0, h1, h2, h3, h4, h5, h6, h7, h8, h9; // iv's

    private int[] x = new int[16];
    private int xoff;

    /**
     * standard constructor
     */
    public ripemd320digest()
    {
        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public ripemd320digest(ripemd320digest t)
    {
        super(t);

        docopy(t);
    }

    private void docopy(ripemd320digest t)
    {
        super.copyin(t);
        h0 = t.h0;
        h1 = t.h1;
        h2 = t.h2;
        h3 = t.h3;
        h4 = t.h4;
        h5 = t.h5;
        h6 = t.h6;
        h7 = t.h7;
        h8 = t.h8;
        h9 = t.h9;
        
        system.arraycopy(t.x, 0, x, 0, t.x.length);
        xoff = t.xoff;
    }

    public string getalgorithmname()
    {
        return "ripemd320";
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
        unpackword(h4, out, outoff + 16);
        unpackword(h5, out, outoff + 20);
        unpackword(h6, out, outoff + 24);
        unpackword(h7, out, outoff + 28);
        unpackword(h8, out, outoff + 32);
        unpackword(h9, out, outoff + 36);

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
        h4 = 0xc3d2e1f0;
        h5 = 0x76543210; 
        h6 = 0xfedcba98;
        h7 = 0x89abcdef; 
        h8 = 0x01234567; 
        h9 = 0x3c2d1e0f;

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
     * f1,f2,f3,f4,f5 are the basic ripemd160 functions.
     */

    /*
     * rounds 0-15
     */
    private int f1(
        int x,
        int y,
        int z)
    {
        return x ^ y ^ z;
    }

    /*
     * rounds 16-31
     */
    private int f2(
        int x,
        int y,
        int z)
    {
        return (x & y) | (~x & z);
    }

    /*
     * rounds 32-47
     */
    private int f3(
        int x,
        int y,
        int z)
    {
        return (x | ~y) ^ z;
    }

    /*
     * rounds 48-63
     */
    private int f4(
        int x,
        int y,
        int z)
    {
        return (x & z) | (y & ~z);
    }

    /*
     * rounds 64-79
     */
    private int f5(
        int x,
        int y,
        int z)
    {
        return x ^ (y | ~z);
    }

    protected void processblock()
    {
        int a, aa;
        int b, bb;
        int c, cc;
        int d, dd;
        int e, ee;
        int t;

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        aa = h5;
        bb = h6;
        cc = h7;
        dd = h8;
        ee = h9;
        
        //
        // rounds 1 - 16
        //
        // left
        a = rl(a + f1(b,c,d) + x[ 0], 11) + e; c = rl(c, 10);
        e = rl(e + f1(a,b,c) + x[ 1], 14) + d; b = rl(b, 10);
        d = rl(d + f1(e,a,b) + x[ 2], 15) + c; a = rl(a, 10);
        c = rl(c + f1(d,e,a) + x[ 3], 12) + b; e = rl(e, 10);
        b = rl(b + f1(c,d,e) + x[ 4],  5) + a; d = rl(d, 10);
        a = rl(a + f1(b,c,d) + x[ 5],  8) + e; c = rl(c, 10);
        e = rl(e + f1(a,b,c) + x[ 6],  7) + d; b = rl(b, 10);
        d = rl(d + f1(e,a,b) + x[ 7],  9) + c; a = rl(a, 10);
        c = rl(c + f1(d,e,a) + x[ 8], 11) + b; e = rl(e, 10);
        b = rl(b + f1(c,d,e) + x[ 9], 13) + a; d = rl(d, 10);
        a = rl(a + f1(b,c,d) + x[10], 14) + e; c = rl(c, 10);
        e = rl(e + f1(a,b,c) + x[11], 15) + d; b = rl(b, 10);
        d = rl(d + f1(e,a,b) + x[12],  6) + c; a = rl(a, 10);
        c = rl(c + f1(d,e,a) + x[13],  7) + b; e = rl(e, 10);
        b = rl(b + f1(c,d,e) + x[14],  9) + a; d = rl(d, 10);
        a = rl(a + f1(b,c,d) + x[15],  8) + e; c = rl(c, 10);

        // right
        aa = rl(aa + f5(bb,cc,dd) + x[ 5] + 0x50a28be6,  8) + ee; cc = rl(cc, 10);
        ee = rl(ee + f5(aa,bb,cc) + x[14] + 0x50a28be6,  9) + dd; bb = rl(bb, 10);
        dd = rl(dd + f5(ee,aa,bb) + x[ 7] + 0x50a28be6,  9) + cc; aa = rl(aa, 10);
        cc = rl(cc + f5(dd,ee,aa) + x[ 0] + 0x50a28be6, 11) + bb; ee = rl(ee, 10);
        bb = rl(bb + f5(cc,dd,ee) + x[ 9] + 0x50a28be6, 13) + aa; dd = rl(dd, 10);
        aa = rl(aa + f5(bb,cc,dd) + x[ 2] + 0x50a28be6, 15) + ee; cc = rl(cc, 10);
        ee = rl(ee + f5(aa,bb,cc) + x[11] + 0x50a28be6, 15) + dd; bb = rl(bb, 10);
        dd = rl(dd + f5(ee,aa,bb) + x[ 4] + 0x50a28be6,  5) + cc; aa = rl(aa, 10);
        cc = rl(cc + f5(dd,ee,aa) + x[13] + 0x50a28be6,  7) + bb; ee = rl(ee, 10);
        bb = rl(bb + f5(cc,dd,ee) + x[ 6] + 0x50a28be6,  7) + aa; dd = rl(dd, 10);
        aa = rl(aa + f5(bb,cc,dd) + x[15] + 0x50a28be6,  8) + ee; cc = rl(cc, 10);
        ee = rl(ee + f5(aa,bb,cc) + x[ 8] + 0x50a28be6, 11) + dd; bb = rl(bb, 10);
        dd = rl(dd + f5(ee,aa,bb) + x[ 1] + 0x50a28be6, 14) + cc; aa = rl(aa, 10);
        cc = rl(cc + f5(dd,ee,aa) + x[10] + 0x50a28be6, 14) + bb; ee = rl(ee, 10);
        bb = rl(bb + f5(cc,dd,ee) + x[ 3] + 0x50a28be6, 12) + aa; dd = rl(dd, 10);
        aa = rl(aa + f5(bb,cc,dd) + x[12] + 0x50a28be6,  6) + ee; cc = rl(cc, 10);

        t = a; a = aa; aa = t;

        //
        // rounds 16-31
        //
        // left
        e = rl(e + f2(a,b,c) + x[ 7] + 0x5a827999,  7) + d; b = rl(b, 10);
        d = rl(d + f2(e,a,b) + x[ 4] + 0x5a827999,  6) + c; a = rl(a, 10);
        c = rl(c + f2(d,e,a) + x[13] + 0x5a827999,  8) + b; e = rl(e, 10);
        b = rl(b + f2(c,d,e) + x[ 1] + 0x5a827999, 13) + a; d = rl(d, 10);
        a = rl(a + f2(b,c,d) + x[10] + 0x5a827999, 11) + e; c = rl(c, 10);
        e = rl(e + f2(a,b,c) + x[ 6] + 0x5a827999,  9) + d; b = rl(b, 10);
        d = rl(d + f2(e,a,b) + x[15] + 0x5a827999,  7) + c; a = rl(a, 10);
        c = rl(c + f2(d,e,a) + x[ 3] + 0x5a827999, 15) + b; e = rl(e, 10);
        b = rl(b + f2(c,d,e) + x[12] + 0x5a827999,  7) + a; d = rl(d, 10);
        a = rl(a + f2(b,c,d) + x[ 0] + 0x5a827999, 12) + e; c = rl(c, 10);
        e = rl(e + f2(a,b,c) + x[ 9] + 0x5a827999, 15) + d; b = rl(b, 10);
        d = rl(d + f2(e,a,b) + x[ 5] + 0x5a827999,  9) + c; a = rl(a, 10);
        c = rl(c + f2(d,e,a) + x[ 2] + 0x5a827999, 11) + b; e = rl(e, 10);
        b = rl(b + f2(c,d,e) + x[14] + 0x5a827999,  7) + a; d = rl(d, 10);
        a = rl(a + f2(b,c,d) + x[11] + 0x5a827999, 13) + e; c = rl(c, 10);
        e = rl(e + f2(a,b,c) + x[ 8] + 0x5a827999, 12) + d; b = rl(b, 10);

        // right
        ee = rl(ee + f4(aa,bb,cc) + x[ 6] + 0x5c4dd124,  9) + dd; bb = rl(bb, 10);
        dd = rl(dd + f4(ee,aa,bb) + x[11] + 0x5c4dd124, 13) + cc; aa = rl(aa, 10);
        cc = rl(cc + f4(dd,ee,aa) + x[ 3] + 0x5c4dd124, 15) + bb; ee = rl(ee, 10);
        bb = rl(bb + f4(cc,dd,ee) + x[ 7] + 0x5c4dd124,  7) + aa; dd = rl(dd, 10);
        aa = rl(aa + f4(bb,cc,dd) + x[ 0] + 0x5c4dd124, 12) + ee; cc = rl(cc, 10);
        ee = rl(ee + f4(aa,bb,cc) + x[13] + 0x5c4dd124,  8) + dd; bb = rl(bb, 10);
        dd = rl(dd + f4(ee,aa,bb) + x[ 5] + 0x5c4dd124,  9) + cc; aa = rl(aa, 10);
        cc = rl(cc + f4(dd,ee,aa) + x[10] + 0x5c4dd124, 11) + bb; ee = rl(ee, 10);
        bb = rl(bb + f4(cc,dd,ee) + x[14] + 0x5c4dd124,  7) + aa; dd = rl(dd, 10);
        aa = rl(aa + f4(bb,cc,dd) + x[15] + 0x5c4dd124,  7) + ee; cc = rl(cc, 10);
        ee = rl(ee + f4(aa,bb,cc) + x[ 8] + 0x5c4dd124, 12) + dd; bb = rl(bb, 10);
        dd = rl(dd + f4(ee,aa,bb) + x[12] + 0x5c4dd124,  7) + cc; aa = rl(aa, 10);
        cc = rl(cc + f4(dd,ee,aa) + x[ 4] + 0x5c4dd124,  6) + bb; ee = rl(ee, 10);
        bb = rl(bb + f4(cc,dd,ee) + x[ 9] + 0x5c4dd124, 15) + aa; dd = rl(dd, 10);
        aa = rl(aa + f4(bb,cc,dd) + x[ 1] + 0x5c4dd124, 13) + ee; cc = rl(cc, 10);
        ee = rl(ee + f4(aa,bb,cc) + x[ 2] + 0x5c4dd124, 11) + dd; bb = rl(bb, 10);

        t = b; b = bb; bb = t;

        //
        // rounds 32-47
        //
        // left
        d = rl(d + f3(e,a,b) + x[ 3] + 0x6ed9eba1, 11) + c; a = rl(a, 10);
        c = rl(c + f3(d,e,a) + x[10] + 0x6ed9eba1, 13) + b; e = rl(e, 10);
        b = rl(b + f3(c,d,e) + x[14] + 0x6ed9eba1,  6) + a; d = rl(d, 10);
        a = rl(a + f3(b,c,d) + x[ 4] + 0x6ed9eba1,  7) + e; c = rl(c, 10);
        e = rl(e + f3(a,b,c) + x[ 9] + 0x6ed9eba1, 14) + d; b = rl(b, 10);
        d = rl(d + f3(e,a,b) + x[15] + 0x6ed9eba1,  9) + c; a = rl(a, 10);
        c = rl(c + f3(d,e,a) + x[ 8] + 0x6ed9eba1, 13) + b; e = rl(e, 10);
        b = rl(b + f3(c,d,e) + x[ 1] + 0x6ed9eba1, 15) + a; d = rl(d, 10);
        a = rl(a + f3(b,c,d) + x[ 2] + 0x6ed9eba1, 14) + e; c = rl(c, 10);
        e = rl(e + f3(a,b,c) + x[ 7] + 0x6ed9eba1,  8) + d; b = rl(b, 10);
        d = rl(d + f3(e,a,b) + x[ 0] + 0x6ed9eba1, 13) + c; a = rl(a, 10);
        c = rl(c + f3(d,e,a) + x[ 6] + 0x6ed9eba1,  6) + b; e = rl(e, 10);
        b = rl(b + f3(c,d,e) + x[13] + 0x6ed9eba1,  5) + a; d = rl(d, 10);
        a = rl(a + f3(b,c,d) + x[11] + 0x6ed9eba1, 12) + e; c = rl(c, 10);
        e = rl(e + f3(a,b,c) + x[ 5] + 0x6ed9eba1,  7) + d; b = rl(b, 10);
        d = rl(d + f3(e,a,b) + x[12] + 0x6ed9eba1,  5) + c; a = rl(a, 10);

        // right
        dd = rl(dd + f3(ee,aa,bb) + x[15] + 0x6d703ef3,  9) + cc; aa = rl(aa, 10);
        cc = rl(cc + f3(dd,ee,aa) + x[ 5] + 0x6d703ef3,  7) + bb; ee = rl(ee, 10);
        bb = rl(bb + f3(cc,dd,ee) + x[ 1] + 0x6d703ef3, 15) + aa; dd = rl(dd, 10);
        aa = rl(aa + f3(bb,cc,dd) + x[ 3] + 0x6d703ef3, 11) + ee; cc = rl(cc, 10);
        ee = rl(ee + f3(aa,bb,cc) + x[ 7] + 0x6d703ef3,  8) + dd; bb = rl(bb, 10);
        dd = rl(dd + f3(ee,aa,bb) + x[14] + 0x6d703ef3,  6) + cc; aa = rl(aa, 10);
        cc = rl(cc + f3(dd,ee,aa) + x[ 6] + 0x6d703ef3,  6) + bb; ee = rl(ee, 10);
        bb = rl(bb + f3(cc,dd,ee) + x[ 9] + 0x6d703ef3, 14) + aa; dd = rl(dd, 10);
        aa = rl(aa + f3(bb,cc,dd) + x[11] + 0x6d703ef3, 12) + ee; cc = rl(cc, 10);
        ee = rl(ee + f3(aa,bb,cc) + x[ 8] + 0x6d703ef3, 13) + dd; bb = rl(bb, 10);
        dd = rl(dd + f3(ee,aa,bb) + x[12] + 0x6d703ef3,  5) + cc; aa = rl(aa, 10);
        cc = rl(cc + f3(dd,ee,aa) + x[ 2] + 0x6d703ef3, 14) + bb; ee = rl(ee, 10);
        bb = rl(bb + f3(cc,dd,ee) + x[10] + 0x6d703ef3, 13) + aa; dd = rl(dd, 10);
        aa = rl(aa + f3(bb,cc,dd) + x[ 0] + 0x6d703ef3, 13) + ee; cc = rl(cc, 10);
        ee = rl(ee + f3(aa,bb,cc) + x[ 4] + 0x6d703ef3,  7) + dd; bb = rl(bb, 10);
        dd = rl(dd + f3(ee,aa,bb) + x[13] + 0x6d703ef3,  5) + cc; aa = rl(aa, 10);

        t = c; c = cc; cc = t;

        //
        // rounds 48-63
        //
        // left
        c = rl(c + f4(d,e,a) + x[ 1] + 0x8f1bbcdc, 11) + b; e = rl(e, 10);
        b = rl(b + f4(c,d,e) + x[ 9] + 0x8f1bbcdc, 12) + a; d = rl(d, 10);
        a = rl(a + f4(b,c,d) + x[11] + 0x8f1bbcdc, 14) + e; c = rl(c, 10);
        e = rl(e + f4(a,b,c) + x[10] + 0x8f1bbcdc, 15) + d; b = rl(b, 10);
        d = rl(d + f4(e,a,b) + x[ 0] + 0x8f1bbcdc, 14) + c; a = rl(a, 10);
        c = rl(c + f4(d,e,a) + x[ 8] + 0x8f1bbcdc, 15) + b; e = rl(e, 10);
        b = rl(b + f4(c,d,e) + x[12] + 0x8f1bbcdc,  9) + a; d = rl(d, 10);
        a = rl(a + f4(b,c,d) + x[ 4] + 0x8f1bbcdc,  8) + e; c = rl(c, 10);
        e = rl(e + f4(a,b,c) + x[13] + 0x8f1bbcdc,  9) + d; b = rl(b, 10);
        d = rl(d + f4(e,a,b) + x[ 3] + 0x8f1bbcdc, 14) + c; a = rl(a, 10);
        c = rl(c + f4(d,e,a) + x[ 7] + 0x8f1bbcdc,  5) + b; e = rl(e, 10);
        b = rl(b + f4(c,d,e) + x[15] + 0x8f1bbcdc,  6) + a; d = rl(d, 10);
        a = rl(a + f4(b,c,d) + x[14] + 0x8f1bbcdc,  8) + e; c = rl(c, 10);
        e = rl(e + f4(a,b,c) + x[ 5] + 0x8f1bbcdc,  6) + d; b = rl(b, 10);
        d = rl(d + f4(e,a,b) + x[ 6] + 0x8f1bbcdc,  5) + c; a = rl(a, 10);
        c = rl(c + f4(d,e,a) + x[ 2] + 0x8f1bbcdc, 12) + b; e = rl(e, 10);

        // right
        cc = rl(cc + f2(dd,ee,aa) + x[ 8] + 0x7a6d76e9, 15) + bb; ee = rl(ee, 10);
        bb = rl(bb + f2(cc,dd,ee) + x[ 6] + 0x7a6d76e9,  5) + aa; dd = rl(dd, 10);
        aa = rl(aa + f2(bb,cc,dd) + x[ 4] + 0x7a6d76e9,  8) + ee; cc = rl(cc, 10);
        ee = rl(ee + f2(aa,bb,cc) + x[ 1] + 0x7a6d76e9, 11) + dd; bb = rl(bb, 10);
        dd = rl(dd + f2(ee,aa,bb) + x[ 3] + 0x7a6d76e9, 14) + cc; aa = rl(aa, 10);
        cc = rl(cc + f2(dd,ee,aa) + x[11] + 0x7a6d76e9, 14) + bb; ee = rl(ee, 10);
        bb = rl(bb + f2(cc,dd,ee) + x[15] + 0x7a6d76e9,  6) + aa; dd = rl(dd, 10);
        aa = rl(aa + f2(bb,cc,dd) + x[ 0] + 0x7a6d76e9, 14) + ee; cc = rl(cc, 10);
        ee = rl(ee + f2(aa,bb,cc) + x[ 5] + 0x7a6d76e9,  6) + dd; bb = rl(bb, 10);
        dd = rl(dd + f2(ee,aa,bb) + x[12] + 0x7a6d76e9,  9) + cc; aa = rl(aa, 10);
        cc = rl(cc + f2(dd,ee,aa) + x[ 2] + 0x7a6d76e9, 12) + bb; ee = rl(ee, 10);
        bb = rl(bb + f2(cc,dd,ee) + x[13] + 0x7a6d76e9,  9) + aa; dd = rl(dd, 10);
        aa = rl(aa + f2(bb,cc,dd) + x[ 9] + 0x7a6d76e9, 12) + ee; cc = rl(cc, 10);
        ee = rl(ee + f2(aa,bb,cc) + x[ 7] + 0x7a6d76e9,  5) + dd; bb = rl(bb, 10);
        dd = rl(dd + f2(ee,aa,bb) + x[10] + 0x7a6d76e9, 15) + cc; aa = rl(aa, 10);
        cc = rl(cc + f2(dd,ee,aa) + x[14] + 0x7a6d76e9,  8) + bb; ee = rl(ee, 10);

       t = d; d = dd; dd = t;

        //
        // rounds 64-79
        //
        // left
        b = rl(b + f5(c,d,e) + x[ 4] + 0xa953fd4e,  9) + a; d = rl(d, 10);
        a = rl(a + f5(b,c,d) + x[ 0] + 0xa953fd4e, 15) + e; c = rl(c, 10);
        e = rl(e + f5(a,b,c) + x[ 5] + 0xa953fd4e,  5) + d; b = rl(b, 10);
        d = rl(d + f5(e,a,b) + x[ 9] + 0xa953fd4e, 11) + c; a = rl(a, 10);
        c = rl(c + f5(d,e,a) + x[ 7] + 0xa953fd4e,  6) + b; e = rl(e, 10);
        b = rl(b + f5(c,d,e) + x[12] + 0xa953fd4e,  8) + a; d = rl(d, 10);
        a = rl(a + f5(b,c,d) + x[ 2] + 0xa953fd4e, 13) + e; c = rl(c, 10);
        e = rl(e + f5(a,b,c) + x[10] + 0xa953fd4e, 12) + d; b = rl(b, 10);
        d = rl(d + f5(e,a,b) + x[14] + 0xa953fd4e,  5) + c; a = rl(a, 10);
        c = rl(c + f5(d,e,a) + x[ 1] + 0xa953fd4e, 12) + b; e = rl(e, 10);
        b = rl(b + f5(c,d,e) + x[ 3] + 0xa953fd4e, 13) + a; d = rl(d, 10);
        a = rl(a + f5(b,c,d) + x[ 8] + 0xa953fd4e, 14) + e; c = rl(c, 10);
        e = rl(e + f5(a,b,c) + x[11] + 0xa953fd4e, 11) + d; b = rl(b, 10);
        d = rl(d + f5(e,a,b) + x[ 6] + 0xa953fd4e,  8) + c; a = rl(a, 10);
        c = rl(c + f5(d,e,a) + x[15] + 0xa953fd4e,  5) + b; e = rl(e, 10);
        b = rl(b + f5(c,d,e) + x[13] + 0xa953fd4e,  6) + a; d = rl(d, 10);

        // right
        bb = rl(bb + f1(cc,dd,ee) + x[12],  8) + aa; dd = rl(dd, 10);
        aa = rl(aa + f1(bb,cc,dd) + x[15],  5) + ee; cc = rl(cc, 10);
        ee = rl(ee + f1(aa,bb,cc) + x[10], 12) + dd; bb = rl(bb, 10);
        dd = rl(dd + f1(ee,aa,bb) + x[ 4],  9) + cc; aa = rl(aa, 10);
        cc = rl(cc + f1(dd,ee,aa) + x[ 1], 12) + bb; ee = rl(ee, 10);
        bb = rl(bb + f1(cc,dd,ee) + x[ 5],  5) + aa; dd = rl(dd, 10);
        aa = rl(aa + f1(bb,cc,dd) + x[ 8], 14) + ee; cc = rl(cc, 10);
        ee = rl(ee + f1(aa,bb,cc) + x[ 7],  6) + dd; bb = rl(bb, 10);
        dd = rl(dd + f1(ee,aa,bb) + x[ 6],  8) + cc; aa = rl(aa, 10);
        cc = rl(cc + f1(dd,ee,aa) + x[ 2], 13) + bb; ee = rl(ee, 10);
        bb = rl(bb + f1(cc,dd,ee) + x[13],  6) + aa; dd = rl(dd, 10);
        aa = rl(aa + f1(bb,cc,dd) + x[14],  5) + ee; cc = rl(cc, 10);
        ee = rl(ee + f1(aa,bb,cc) + x[ 0], 15) + dd; bb = rl(bb, 10);
        dd = rl(dd + f1(ee,aa,bb) + x[ 3], 13) + cc; aa = rl(aa, 10);
        cc = rl(cc + f1(dd,ee,aa) + x[ 9], 11) + bb; ee = rl(ee, 10);
        bb = rl(bb + f1(cc,dd,ee) + x[11], 11) + aa; dd = rl(dd, 10);

        //
        // do (e, ee) swap as part of assignment.
        //

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += ee;
        h5 += aa;
        h6 += bb;
        h7 += cc;
        h8 += dd;
        h9 += e;
        
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
        return new ripemd320digest(this);
    }

    public void reset(memoable other)
    {
        ripemd320digest d = (ripemd320digest)other;

        docopy(d);
    }
}
