package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.memoable;

/**
 * implementation of sha-1 as outlined in "handbook of applied cryptography", pages 346 - 349.
 *
 * it is interesting to ponder why the, apart from the extra iv, the other difference here from md5
 * is the "endianness" of the word processing!
 */
public class sha1digest
    extends generaldigest
{
    private static final int    digest_length = 20;

    private int     h1, h2, h3, h4, h5;

    private int[]   x = new int[80];
    private int     xoff;

    /**
     * standard constructor
     */
    public sha1digest()
    {
        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public sha1digest(sha1digest t)
    {
        super(t);

        copyin(t);
    }

    private void copyin(sha1digest t)
    {
        h1 = t.h1;
        h2 = t.h2;
        h3 = t.h3;
        h4 = t.h4;
        h5 = t.h5;

        system.arraycopy(t.x, 0, x, 0, t.x.length);
        xoff = t.xoff;
    }

    public string getalgorithmname()
    {
        return "sha-1";
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

        reset();

        return digest_length;
    }

    /**
     * reset the chaining variables
     */
    public void reset()
    {
        super.reset();

        h1 = 0x67452301;
        h2 = 0xefcdab89;
        h3 = 0x98badcfe;
        h4 = 0x10325476;
        h5 = 0xc3d2e1f0;

        xoff = 0;
        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }
    }

    //
    // additive constants
    //
    private static final int    y1 = 0x5a827999;
    private static final int    y2 = 0x6ed9eba1;
    private static final int    y3 = 0x8f1bbcdc;
    private static final int    y4 = 0xca62c1d6;
   
    private int f(
        int    u,
        int    v,
        int    w)
    {
        return ((u & v) | ((~u) & w));
    }

    private int h(
        int    u,
        int    v,
        int    w)
    {
        return (u ^ v ^ w);
    }

    private int g(
        int    u,
        int    v,
        int    w)
    {
        return ((u & v) | (u & w) | (v & w));
    }

    protected void processblock()
    {
        //
        // expand 16 word block into 80 word block.
        //
        for (int i = 16; i < 80; i++)
        {
            int t = x[i - 3] ^ x[i - 8] ^ x[i - 14] ^ x[i - 16];
            x[i] = t << 1 | t >>> 31;
        }

        //
        // set up working variables.
        //
        int     a = h1;
        int     b = h2;
        int     c = h3;
        int     d = h4;
        int     e = h5;

        //
        // round 1
        //
        int idx = 0;
        
        for (int j = 0; j < 4; j++)
        {
            // e = rotateleft(a, 5) + f(b, c, d) + e + x[idx++] + y1
            // b = rotateleft(b, 30)
            e += (a << 5 | a >>> 27) + f(b, c, d) + x[idx++] + y1;
            b = b << 30 | b >>> 2;
        
            d += (e << 5 | e >>> 27) + f(a, b, c) + x[idx++] + y1;
            a = a << 30 | a >>> 2;
       
            c += (d << 5 | d >>> 27) + f(e, a, b) + x[idx++] + y1;
            e = e << 30 | e >>> 2;
       
            b += (c << 5 | c >>> 27) + f(d, e, a) + x[idx++] + y1;
            d = d << 30 | d >>> 2;

            a += (b << 5 | b >>> 27) + f(c, d, e) + x[idx++] + y1;
            c = c << 30 | c >>> 2;
        }
        
        //
        // round 2
        //
        for (int j = 0; j < 4; j++)
        {
            // e = rotateleft(a, 5) + h(b, c, d) + e + x[idx++] + y2
            // b = rotateleft(b, 30)
            e += (a << 5 | a >>> 27) + h(b, c, d) + x[idx++] + y2;
            b = b << 30 | b >>> 2;   
            
            d += (e << 5 | e >>> 27) + h(a, b, c) + x[idx++] + y2;
            a = a << 30 | a >>> 2;
            
            c += (d << 5 | d >>> 27) + h(e, a, b) + x[idx++] + y2;
            e = e << 30 | e >>> 2;
            
            b += (c << 5 | c >>> 27) + h(d, e, a) + x[idx++] + y2;
            d = d << 30 | d >>> 2;

            a += (b << 5 | b >>> 27) + h(c, d, e) + x[idx++] + y2;
            c = c << 30 | c >>> 2;
        }
        
        //
        // round 3
        //
        for (int j = 0; j < 4; j++)
        {
            // e = rotateleft(a, 5) + g(b, c, d) + e + x[idx++] + y3
            // b = rotateleft(b, 30)
            e += (a << 5 | a >>> 27) + g(b, c, d) + x[idx++] + y3;
            b = b << 30 | b >>> 2;
            
            d += (e << 5 | e >>> 27) + g(a, b, c) + x[idx++] + y3;
            a = a << 30 | a >>> 2;
            
            c += (d << 5 | d >>> 27) + g(e, a, b) + x[idx++] + y3;
            e = e << 30 | e >>> 2;
            
            b += (c << 5 | c >>> 27) + g(d, e, a) + x[idx++] + y3;
            d = d << 30 | d >>> 2;

            a += (b << 5 | b >>> 27) + g(c, d, e) + x[idx++] + y3;
            c = c << 30 | c >>> 2;
        }

        //
        // round 4
        //
        for (int j = 0; j <= 3; j++)
        {
            // e = rotateleft(a, 5) + h(b, c, d) + e + x[idx++] + y4
            // b = rotateleft(b, 30)
            e += (a << 5 | a >>> 27) + h(b, c, d) + x[idx++] + y4;
            b = b << 30 | b >>> 2;
            
            d += (e << 5 | e >>> 27) + h(a, b, c) + x[idx++] + y4;
            a = a << 30 | a >>> 2;
            
            c += (d << 5 | d >>> 27) + h(e, a, b) + x[idx++] + y4;
            e = e << 30 | e >>> 2;
            
            b += (c << 5 | c >>> 27) + h(d, e, a) + x[idx++] + y4;
            d = d << 30 | d >>> 2;

            a += (b << 5 | b >>> 27) + h(c, d, e) + x[idx++] + y4;
            c = c << 30 | c >>> 2;
        }


        h1 += a;
        h2 += b;
        h3 += c;
        h4 += d;
        h5 += e;

        //
        // reset start of the buffer.
        //
        xoff = 0;
        for (int i = 0; i < 16; i++)
        {
            x[i] = 0;
        }
    }

    public memoable copy()
    {
        return new sha1digest(this);
    }

    public void reset(memoable other)
    {
        sha1digest d = (sha1digest)other;

        super.copyin(d);
        copyin(d);
    }
}




