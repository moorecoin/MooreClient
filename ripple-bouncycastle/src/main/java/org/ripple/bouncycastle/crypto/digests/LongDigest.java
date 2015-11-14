package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.memoable;

/**
 * base class for sha-384 and sha-512.
 */
public abstract class longdigest
    implements extendeddigest, memoable
{
    private static final int byte_length = 128;
    
    private byte[]  xbuf;
    private int     xbufoff;

    private long    bytecount1;
    private long    bytecount2;

    protected long    h1, h2, h3, h4, h5, h6, h7, h8;

    private long[]  w = new long[80];
    private int     woff;

    /**
     * constructor for variable length word
     */
    protected longdigest()
    {
        xbuf = new byte[8];
        xbufoff = 0;

        reset();
    }

    /**
     * copy constructor.  we are using copy constructors in place
     * of the object.clone() interface as this interface is not
     * supported by j2me.
     */
    protected longdigest(longdigest t)
    {
        xbuf = new byte[t.xbuf.length];

        copyin(t);
    }

    protected void copyin(longdigest t)
    {
        system.arraycopy(t.xbuf, 0, xbuf, 0, t.xbuf.length);

        xbufoff = t.xbufoff;
        bytecount1 = t.bytecount1;
        bytecount2 = t.bytecount2;

        h1 = t.h1;
        h2 = t.h2;
        h3 = t.h3;
        h4 = t.h4;
        h5 = t.h5;
        h6 = t.h6;
        h7 = t.h7;
        h8 = t.h8;

        system.arraycopy(t.w, 0, w, 0, t.w.length);
        woff = t.woff;
    }

    public void update(
        byte in)
    {
        xbuf[xbufoff++] = in;

        if (xbufoff == xbuf.length)
        {
            processword(xbuf, 0);
            xbufoff = 0;
        }

        bytecount1++;
    }

    public void update(
        byte[]  in,
        int     inoff,
        int     len)
    {
        //
        // fill the current word
        //
        while ((xbufoff != 0) && (len > 0))
        {
            update(in[inoff]);

            inoff++;
            len--;
        }

        //
        // process whole words.
        //
        while (len > xbuf.length)
        {
            processword(in, inoff);

            inoff += xbuf.length;
            len -= xbuf.length;
            bytecount1 += xbuf.length;
        }

        //
        // load in the remainder.
        //
        while (len > 0)
        {
            update(in[inoff]);

            inoff++;
            len--;
        }
    }

    public void finish()
    {
        adjustbytecounts();

        long    lowbitlength = bytecount1 << 3;
        long    hibitlength = bytecount2;

        //
        // add the pad bytes.
        //
        update((byte)128);

        while (xbufoff != 0)
        {
            update((byte)0);
        }

        processlength(lowbitlength, hibitlength);

        processblock();
    }

    public void reset()
    {
        bytecount1 = 0;
        bytecount2 = 0;

        xbufoff = 0;
        for (int i = 0; i < xbuf.length; i++)
        {
            xbuf[i] = 0;
        }

        woff = 0;
        for (int i = 0; i != w.length; i++)
        {
            w[i] = 0;
        }
    }

    public int getbytelength()
    {
        return byte_length;
    }
    
    protected void processword(
        byte[]  in,
        int     inoff)
    {
        w[woff] = pack.bigendiantolong(in, inoff);

        if (++woff == 16)
        {
            processblock();
        }
    }

    /**
     * adjust the byte counts so that bytecount2 represents the
     * upper long (less 3 bits) word of the byte count.
     */
    private void adjustbytecounts()
    {
        if (bytecount1 > 0x1fffffffffffffffl)
        {
            bytecount2 += (bytecount1 >>> 61);
            bytecount1 &= 0x1fffffffffffffffl;
        }
    }

    protected void processlength(
        long    loww,
        long    hiw)
    {
        if (woff > 14)
        {
            processblock();
        }

        w[14] = hiw;
        w[15] = loww;
    }

    protected void processblock()
    {
        adjustbytecounts();

        //
        // expand 16 word block into 80 word blocks.
        //
        for (int t = 16; t <= 79; t++)
        {
            w[t] = sigma1(w[t - 2]) + w[t - 7] + sigma0(w[t - 15]) + w[t - 16];
        }

        //
        // set up working variables.
        //
        long     a = h1;
        long     b = h2;
        long     c = h3;
        long     d = h4;
        long     e = h5;
        long     f = h6;
        long     g = h7;
        long     h = h8;

        int t = 0;     
        for(int i = 0; i < 10; i ++)
        {
          // t = 8 * i
          h += sum1(e) + ch(e, f, g) + k[t] + w[t++];
          d += h;
          h += sum0(a) + maj(a, b, c);

          // t = 8 * i + 1
          g += sum1(d) + ch(d, e, f) + k[t] + w[t++];
          c += g;
          g += sum0(h) + maj(h, a, b);

          // t = 8 * i + 2
          f += sum1(c) + ch(c, d, e) + k[t] + w[t++];
          b += f;
          f += sum0(g) + maj(g, h, a);

          // t = 8 * i + 3
          e += sum1(b) + ch(b, c, d) + k[t] + w[t++];
          a += e;
          e += sum0(f) + maj(f, g, h);

          // t = 8 * i + 4
          d += sum1(a) + ch(a, b, c) + k[t] + w[t++];
          h += d;
          d += sum0(e) + maj(e, f, g);

          // t = 8 * i + 5
          c += sum1(h) + ch(h, a, b) + k[t] + w[t++];
          g += c;
          c += sum0(d) + maj(d, e, f);

          // t = 8 * i + 6
          b += sum1(g) + ch(g, h, a) + k[t] + w[t++];
          f += b;
          b += sum0(c) + maj(c, d, e);

          // t = 8 * i + 7
          a += sum1(f) + ch(f, g, h) + k[t] + w[t++];
          e += a;
          a += sum0(b) + maj(b, c, d);
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
        woff = 0;
        for (int i = 0; i < 16; i++)
        {
            w[i] = 0;
        }
    }

    /* sha-384 and sha-512 functions (as for sha-256 but for longs) */
    private long ch(
        long    x,
        long    y,
        long    z)
    {
        return ((x & y) ^ ((~x) & z));
    }

    private long maj(
        long    x,
        long    y,
        long    z)
    {
        return ((x & y) ^ (x & z) ^ (y & z));
    }

    private long sum0(
        long    x)
    {
        return ((x << 36)|(x >>> 28)) ^ ((x << 30)|(x >>> 34)) ^ ((x << 25)|(x >>> 39));
    }

    private long sum1(
        long    x)
    {
        return ((x << 50)|(x >>> 14)) ^ ((x << 46)|(x >>> 18)) ^ ((x << 23)|(x >>> 41));
    }

    private long sigma0(
        long    x)
    {
        return ((x << 63)|(x >>> 1)) ^ ((x << 56)|(x >>> 8)) ^ (x >>> 7);
    }

    private long sigma1(
        long    x)
    {
        return ((x << 45)|(x >>> 19)) ^ ((x << 3)|(x >>> 61)) ^ (x >>> 6);
    }

    /* sha-384 and sha-512 constants
     * (represent the first 64 bits of the fractional parts of the
     * cube roots of the first sixty-four prime numbers)
     */
    static final long k[] = {
0x428a2f98d728ae22l, 0x7137449123ef65cdl, 0xb5c0fbcfec4d3b2fl, 0xe9b5dba58189dbbcl,
0x3956c25bf348b538l, 0x59f111f1b605d019l, 0x923f82a4af194f9bl, 0xab1c5ed5da6d8118l,
0xd807aa98a3030242l, 0x12835b0145706fbel, 0x243185be4ee4b28cl, 0x550c7dc3d5ffb4e2l,
0x72be5d74f27b896fl, 0x80deb1fe3b1696b1l, 0x9bdc06a725c71235l, 0xc19bf174cf692694l,
0xe49b69c19ef14ad2l, 0xefbe4786384f25e3l, 0x0fc19dc68b8cd5b5l, 0x240ca1cc77ac9c65l,
0x2de92c6f592b0275l, 0x4a7484aa6ea6e483l, 0x5cb0a9dcbd41fbd4l, 0x76f988da831153b5l,
0x983e5152ee66dfabl, 0xa831c66d2db43210l, 0xb00327c898fb213fl, 0xbf597fc7beef0ee4l,
0xc6e00bf33da88fc2l, 0xd5a79147930aa725l, 0x06ca6351e003826fl, 0x142929670a0e6e70l,
0x27b70a8546d22ffcl, 0x2e1b21385c26c926l, 0x4d2c6dfc5ac42aedl, 0x53380d139d95b3dfl,
0x650a73548baf63del, 0x766a0abb3c77b2a8l, 0x81c2c92e47edaee6l, 0x92722c851482353bl,
0xa2bfe8a14cf10364l, 0xa81a664bbc423001l, 0xc24b8b70d0f89791l, 0xc76c51a30654be30l,
0xd192e819d6ef5218l, 0xd69906245565a910l, 0xf40e35855771202al, 0x106aa07032bbd1b8l,
0x19a4c116b8d2d0c8l, 0x1e376c085141ab53l, 0x2748774cdf8eeb99l, 0x34b0bcb5e19b48a8l,
0x391c0cb3c5c95a63l, 0x4ed8aa4ae3418acbl, 0x5b9cca4f7763e373l, 0x682e6ff3d6b2b8a3l,
0x748f82ee5defb2fcl, 0x78a5636f43172f60l, 0x84c87814a1f0ab72l, 0x8cc702081a6439ecl,
0x90befffa23631e28l, 0xa4506cebde82bde9l, 0xbef9a3f7b2c67915l, 0xc67178f2e372532bl,
0xca273eceea26619cl, 0xd186b8c721c0c207l, 0xeada7dd6cde0eb1el, 0xf57d4f7fee6ed178l,
0x06f067aa72176fbal, 0x0a637dc5a2c898a6l, 0x113f9804bef90dael, 0x1b710b35131c471bl,
0x28db77f523047d84l, 0x32caab7b40c72493l, 0x3c9ebe0a15c9bebcl, 0x431d67c49c100d4cl,
0x4cc5d4becb3e42b6l, 0x597f299cfc657e2al, 0x5fcb6fab3ad6faecl, 0x6c44198c4a475817l
    };
}
