package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.util.memoable;

/**
 * base implementation of md4 family style digest as outlined in
 * "handbook of applied cryptography", pages 344 - 347.
 */
public abstract class generaldigest
    implements extendeddigest, memoable
{
    private static final int byte_length = 64;
    private byte[]  xbuf;
    private int     xbufoff;

    private long    bytecount;

    /**
     * standard constructor
     */
    protected generaldigest()
    {
        xbuf = new byte[4];
        xbufoff = 0;
    }

    /**
     * copy constructor.  we are using copy constructors in place
     * of the object.clone() interface as this interface is not
     * supported by j2me.
     */
    protected generaldigest(generaldigest t)
    {
        xbuf = new byte[t.xbuf.length];

        copyin(t);
    }

    protected void copyin(generaldigest t)
    {
        system.arraycopy(t.xbuf, 0, xbuf, 0, t.xbuf.length);

        xbufoff = t.xbufoff;
        bytecount = t.bytecount;
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

        bytecount++;
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
            bytecount += xbuf.length;
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
        long    bitlength = (bytecount << 3);

        //
        // add the pad bytes.
        //
        update((byte)128);

        while (xbufoff != 0)
        {
            update((byte)0);
        }

        processlength(bitlength);

        processblock();
    }

    public void reset()
    {
        bytecount = 0;

        xbufoff = 0;
        for (int i = 0; i < xbuf.length; i++)
        {
            xbuf[i] = 0;
        }
    }

    public int getbytelength()
    {
        return byte_length;
    }
    
    protected abstract void processword(byte[] in, int inoff);

    protected abstract void processlength(long bitlength);

    protected abstract void processblock();
}
