package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.crypto.engines.gost28147engine;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithsbox;
import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.memoable;

/**
 * implementation of gost r 34.11-94
 */
public class gost3411digest
    implements extendeddigest, memoable
{
    private static final int    digest_length = 32;

    private byte[]   h = new byte[32], l = new byte[32],
                     m = new byte[32], sum = new byte[32];
    private byte[][] c = new byte[4][32];

    private byte[]  xbuf = new byte[32];
    private int  xbufoff;
    private long bytecount;
    
    private blockcipher cipher = new gost28147engine();
    private byte[] sbox;

    /**
     * standard constructor
     */
    public gost3411digest()
    {
        sbox = gost28147engine.getsbox("d-a");
        cipher.init(true, new parameterswithsbox(null, sbox));

        reset();
    }

    /**
     * constructor to allow use of a particular sbox with gost28147
     * @see gost28147engine#getsbox(string)
     */
    public gost3411digest(byte[] sboxparam)
    {
        sbox = arrays.clone(sboxparam);
        cipher.init(true, new parameterswithsbox(null, sbox));

        reset();
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public gost3411digest(gost3411digest t)
    {
        reset(t);
    }

    public string getalgorithmname()
    {
        return "gost3411";
    }

    public int getdigestsize()
    {
        return digest_length;
    }

    public void update(byte in)
    {
        xbuf[xbufoff++] = in;
        if (xbufoff == xbuf.length)
        {
            sumbytearray(xbuf); // calc sum m
            processblock(xbuf, 0);
            xbufoff = 0;
        }
        bytecount++;
    }

    public void update(byte[] in, int inoff, int len)
    {
        while ((xbufoff != 0) && (len > 0))
        {
            update(in[inoff]);
            inoff++;
            len--;
        }

        while (len > xbuf.length)
        {
            system.arraycopy(in, inoff, xbuf, 0, xbuf.length);

            sumbytearray(xbuf); // calc sum m
            processblock(xbuf, 0);
            inoff += xbuf.length;
            len -= xbuf.length;
            bytecount += xbuf.length;
        }

        // load in the remainder.
        while (len > 0)
        {
            update(in[inoff]);
            inoff++;
            len--;
        }
    }

    // (i + 1 + 4(k - 1)) = 8i + k      i = 0-3, k = 1-8
    private byte[] k = new byte[32];

    private byte[] p(byte[] in)
    {
        for(int k = 0; k < 8; k++)
        {
            k[4*k] = in[k];
            k[1 + 4*k] = in[ 8 + k];
            k[2 + 4*k] = in[16 + k];
            k[3 + 4*k] = in[24 + k];
        }

        return k;
    }

    //a (x) = (x0 ^ x1) || x3 || x2 || x1
    byte[] a = new byte[8];
    private byte[] a(byte[] in)
    {
        for(int j=0; j<8; j++)
        {
            a[j]=(byte)(in[j] ^ in[j+8]);
        }

        system.arraycopy(in, 8, in, 0, 24);
        system.arraycopy(a, 0, in, 24, 8);

        return in;
    }

    //encrypt function, ecb mode
    private void e(byte[] key, byte[] s, int soff, byte[] in, int inoff)
    {
        cipher.init(true, new keyparameter(key));
        
        cipher.processblock(in, inoff, s, soff);
    }

    // (in:) n16||..||n1 ==> (out:) n1^n2^n3^n4^n13^n16||n16||..||n2
    short[] ws = new short[16], w_s = new short[16];

    private void fw(byte[] in)
    {
        cpybytestoshort(in, ws);
        w_s[15] = (short)(ws[0] ^ ws[1] ^ ws[2] ^ ws[3] ^ ws[12] ^ ws[15]);
        system.arraycopy(ws, 1, w_s, 0, 15);
        cpyshorttobytes(w_s, in);
    }

    // block processing
    byte[] s = new byte[32];
    byte[] u = new byte[32], v = new byte[32], w = new byte[32];

    protected void processblock(byte[] in, int inoff)
    {
        system.arraycopy(in, inoff, m, 0, 32);

        //key step 1
 
        // h = h3 || h2 || h1 || h0
        // s = s3 || s2 || s1 || s0
        system.arraycopy(h, 0, u, 0, 32);
        system.arraycopy(m, 0, v, 0, 32);
        for (int j=0; j<32; j++)
        {
            w[j] = (byte)(u[j]^v[j]);
        }
        // encrypt gost28147-ecb
        e(p(w), s, 0, h, 0); // s0 = ek0 [h0]

        //keys step 2,3,4
        for (int i=1; i<4; i++)
        {
            byte[] tmpa = a(u);
            for (int j=0; j<32; j++)
            {
                u[j] = (byte)(tmpa[j] ^ c[i][j]);
            }
            v = a(a(v));
            for (int j=0; j<32; j++)
            {
                w[j] = (byte)(u[j]^v[j]);
            }
            // encrypt gost28147-ecb
            e(p(w), s, i * 8, h, i * 8); // si = eki [hi]
        }

        // x(m, h) = y61(h^y(m^y12(s)))
        for(int n = 0; n < 12; n++)
        {
            fw(s);
        }
        for(int n = 0; n < 32; n++)
        {
            s[n] = (byte)(s[n] ^ m[n]);
        }

        fw(s);

        for(int n = 0; n < 32; n++)
        {
            s[n] = (byte)(h[n] ^ s[n]);
        }
        for(int n = 0; n < 61; n++)
        {
            fw(s);
        }
        system.arraycopy(s, 0, h, 0, h.length);
    }

    private void finish()
    {
        pack.longtolittleendian(bytecount * 8, l, 0); // get length into l (bytecount * 8 = bitcount)

        while (xbufoff != 0)
        {
            update((byte)0);
        }

        processblock(l, 0);
        processblock(sum, 0);
    }

    public int dofinal(
        byte[]  out,
        int     outoff)
    {
        finish();

        system.arraycopy(h, 0, out, outoff, h.length);

        reset();

        return digest_length;
    }

    /**
     * reset the chaining variables to the iv values.
     */
    private static final byte[]  c2 = {
       0x00,(byte)0xff,0x00,(byte)0xff,0x00,(byte)0xff,0x00,(byte)0xff,
       (byte)0xff,0x00,(byte)0xff,0x00,(byte)0xff,0x00,(byte)0xff,0x00,
       0x00,(byte)0xff,(byte)0xff,0x00,(byte)0xff,0x00,0x00,(byte)0xff,
       (byte)0xff,0x00,0x00,0x00,(byte)0xff,(byte)0xff,0x00,(byte)0xff};

    public void reset()
    {
        bytecount = 0;
        xbufoff = 0;

        for(int i=0; i<h.length; i++)
        {
            h[i] = 0;  // start vector h
        }
        for(int i=0; i<l.length; i++)
        {
            l[i] = 0;
        }
        for(int i=0; i<m.length; i++)
        {
            m[i] = 0;
        }
        for(int i=0; i<c[1].length; i++)
        {
            c[1][i] = 0;  // real index c = +1 because index array with 0.
        }
        for(int i=0; i<c[3].length; i++)
        {
            c[3][i] = 0;
        }
        for(int i=0; i<sum.length; i++)
        {
            sum[i] = 0;
        }
        for(int i = 0; i < xbuf.length; i++)
        {
            xbuf[i] = 0;
        }

        system.arraycopy(c2, 0, c[2], 0, c2.length);
    }

    //  256 bitsblock modul -> (sum + a mod (2^256))
    private void sumbytearray(byte[] in)
    {
        int carry = 0;

        for (int i = 0; i != sum.length; i++)
        {
            int sum = (sum[i] & 0xff) + (in[i] & 0xff) + carry;

            sum[i] = (byte)sum;

            carry = sum >>> 8;
        }
    }

    private void cpybytestoshort(byte[] s, short[] ws)
    {
        for(int i=0; i<s.length/2; i++)
        {
            ws[i] = (short)(((s[i*2+1]<<8)&0xff00)|(s[i*2]&0xff));
        }
    }

    private void cpyshorttobytes(short[] ws, byte[] s)
    {
        for(int i=0; i<s.length/2; i++) 
        {
            s[i*2 + 1] = (byte)(ws[i] >> 8);
            s[i*2] = (byte)ws[i];
        }
    }

   public int getbytelength() 
   {
      return 32;
   }

    public memoable copy()
    {
        return new gost3411digest(this);
    }

    public void reset(memoable other)
    {
        gost3411digest t = (gost3411digest)other;

        this.sbox = t.sbox;
        cipher.init(true, new parameterswithsbox(null, sbox));

        reset();

        system.arraycopy(t.h, 0, this.h, 0, t.h.length);
        system.arraycopy(t.l, 0, this.l, 0, t.l.length);
        system.arraycopy(t.m, 0, this.m, 0, t.m.length);
        system.arraycopy(t.sum, 0, this.sum, 0, t.sum.length);
        system.arraycopy(t.c[1], 0, this.c[1], 0, t.c[1].length);
        system.arraycopy(t.c[2], 0, this.c[2], 0, t.c[2].length);
        system.arraycopy(t.c[3], 0, this.c[3], 0, t.c[3].length);
        system.arraycopy(t.xbuf, 0, this.xbuf, 0, t.xbuf.length);

        this.xbufoff = t.xbufoff;
        this.bytecount = t.bytecount;
    }
}


