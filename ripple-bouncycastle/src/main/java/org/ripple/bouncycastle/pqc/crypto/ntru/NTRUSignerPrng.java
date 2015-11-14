package org.ripple.bouncycastle.pqc.crypto.ntru;

import java.nio.bytebuffer;

import org.ripple.bouncycastle.crypto.digest;

/**
 * an implementation of the deterministic pseudo-random generator in eess section 3.7.3.1
 */
public class ntrusignerprng
{
    private int counter;
    private byte[] seed;
    private digest hashalg;

    /**
     * constructs a new prng and seeds it with a byte array.
     *
     * @param seed    a seed
     * @param hashalg the hash algorithm to use
     */
    ntrusignerprng(byte[] seed, digest hashalg)
    {
        counter = 0;
        this.seed = seed;
        this.hashalg = hashalg;
    }

    /**
     * returns <code>n</code> random bytes
     *
     * @param n number of bytes to return
     * @return the next <code>n</code> random bytes
     */
    byte[] nextbytes(int n)
    {
        bytebuffer buf = bytebuffer.allocate(n);

        while (buf.hasremaining())
        {
            bytebuffer cbuf = bytebuffer.allocate(seed.length + 4);
            cbuf.put(seed);
            cbuf.putint(counter);
            byte[] array = cbuf.array();
            byte[] hash = new byte[hashalg.getdigestsize()];

            hashalg.update(array, 0, array.length);

            hashalg.dofinal(hash, 0);

            if (buf.remaining() < hash.length)
            {
                buf.put(hash, 0, buf.remaining());
            }
            else
            {
                buf.put(hash);
            }
            counter++;
        }

        return buf.array();
    }
}