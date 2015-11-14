package org.ripple.bouncycastle.pqc.crypto.ntru;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.util.arrays;

/**
 * an implementation of the index generation function in ieee p1363.1.
 */
public class indexgenerator
{
    private byte[] seed;
    private int n;
    private int c;
    private int mincallsr;
    private int totlen;
    private int remlen;
    private bitstring buf;
    private int counter;
    private boolean initialized;
    private digest hashalg;
    private int hlen;

    /**
     * constructs a new index generator.
     *
     * @param seed   a seed of arbitrary length to initialize the index generator with
     * @param params ntruencrypt parameters
     */
    indexgenerator(byte[] seed, ntruencryptionparameters params)
    {
        this.seed = seed;
        n = params.n;
        c = params.c;
        mincallsr = params.mincallsr;

        totlen = 0;
        remlen = 0;
        counter = 0;
        hashalg = params.hashalg;

        hlen = hashalg.getdigestsize();   // hash length
        initialized = false;
    }

    /**
     * returns a number <code>i</code> such that <code>0 &lt;= i &lt; n</code>.
     *
     * @return
     */
    int nextindex()
    {
        if (!initialized)
        {
            buf = new bitstring();
            byte[] hash = new byte[hashalg.getdigestsize()];
            while (counter < mincallsr)
            {
                appendhash(buf, hash);
                counter++;
            }
            totlen = mincallsr * 8 * hlen;
            remlen = totlen;
            initialized = true;
        }

        while (true)
        {
            totlen += c;
            bitstring m = buf.gettrailing(remlen);
            if (remlen < c)
            {
                int tmplen = c - remlen;
                int cthreshold = counter + (tmplen + hlen - 1) / hlen;
                byte[] hash = new byte[hashalg.getdigestsize()];
                while (counter < cthreshold)
                {
                    appendhash(m, hash);
                    counter++;
                    if (tmplen > 8 * hlen)
                    {
                        tmplen -= 8 * hlen;
                    }
                }
                remlen = 8 * hlen - tmplen;
                buf = new bitstring();
                buf.appendbits(hash);
            }
            else
            {
                remlen -= c;
            }

            int i = m.getleadingasint(c);   // assume c<32
            if (i < (1 << c) - ((1 << c) % n))
            {
                return i % n;
            }
        }
    }

    private void appendhash(bitstring m, byte[] hash)
    {
        hashalg.update(seed, 0, seed.length);

        putint(hashalg, counter);

        hashalg.dofinal(hash, 0);

        m.appendbits(hash);
    }

    private void putint(digest hashalg, int counter)
    {
        hashalg.update((byte)(counter >> 24));
        hashalg.update((byte)(counter >> 16));
        hashalg.update((byte)(counter >> 8));
        hashalg.update((byte)counter);
    }

    /**
     * represents a string of bits and supports appending, reading the head, and reading the tail.
     */
    public static class bitstring
    {
        byte[] bytes = new byte[4];
        int numbytes;   // includes the last byte even if only some of its bits are used
        int lastbytebits;   // lastbytebits <= 8

        /**
         * appends all bits in a byte array to the end of the bit string.
         *
         * @param bytes a byte array
         */
        void appendbits(byte[] bytes)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                appendbits(bytes[i]);
            }
        }

        /**
         * appends all bits in a byte to the end of the bit string.
         *
         * @param b a byte
         */
        public void appendbits(byte b)
        {
            if (numbytes == bytes.length)
            {
                bytes = copyof(bytes, 2 * bytes.length);
            }

            if (numbytes == 0)
            {
                numbytes = 1;
                bytes[0] = b;
                lastbytebits = 8;
            }
            else if (lastbytebits == 8)
            {
                bytes[numbytes++] = b;
            }
            else
            {
                int s = 8 - lastbytebits;
                bytes[numbytes - 1] |= (b & 0xff) << lastbytebits;
                bytes[numbytes++] = (byte)((b & 0xff) >> s);
            }
        }

        /**
         * returns the last <code>numbits</code> bits from the end of the bit string.
         *
         * @param numbits number of bits
         * @return a new <code>bitstring</code> of length <code>numbits</code>
         */
        public bitstring gettrailing(int numbits)
        {
            bitstring newstr = new bitstring();
            newstr.numbytes = (numbits + 7) / 8;
            newstr.bytes = new byte[newstr.numbytes];
            for (int i = 0; i < newstr.numbytes; i++)
            {
                newstr.bytes[i] = bytes[i];
            }

            newstr.lastbytebits = numbits % 8;
            if (newstr.lastbytebits == 0)
            {
                newstr.lastbytebits = 8;
            }
            else
            {
                int s = 32 - newstr.lastbytebits;
                newstr.bytes[newstr.numbytes - 1] = (byte)(newstr.bytes[newstr.numbytes - 1] << s >>> s);
            }

            return newstr;
        }

        /**
         * returns up to 32 bits from the beginning of the bit string.
         *
         * @param numbits number of bits
         * @return an <code>int</code> whose lower <code>numbits</code> bits are the beginning of the bit string
         */
        public int getleadingasint(int numbits)
        {
            int startbit = (numbytes - 1) * 8 + lastbytebits - numbits;
            int startbyte = startbit / 8;

            int startbitinstartbyte = startbit % 8;
            int sum = (bytes[startbyte] & 0xff) >>> startbitinstartbyte;
            int shift = 8 - startbitinstartbyte;
            for (int i = startbyte + 1; i < numbytes; i++)
            {
                sum |= (bytes[i] & 0xff) << shift;
                shift += 8;
            }

            return sum;
        }

        public byte[] getbytes()
        {
            return arrays.clone(bytes);
        }
    }

    private static byte[] copyof(byte[] src, int len)
    {
        byte[] tmp = new byte[len];

        system.arraycopy(src, 0, tmp, 0, len < src.length ? len : src.length);

        return tmp;
    }
}