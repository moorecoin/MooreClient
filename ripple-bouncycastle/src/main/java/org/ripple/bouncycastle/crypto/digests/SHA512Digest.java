package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.memoable;


/**
 * fips 180-2 implementation of sha-512.
 *
 * <pre>
 *         block  word  digest
 * sha-1   512    32    160
 * sha-256 512    32    256
 * sha-384 1024   64    384
 * sha-512 1024   64    512
 * </pre>
 */
public class sha512digest
    extends longdigest
{
    private static final int    digest_length = 64;

    /**
     * standard constructor
     */
    public sha512digest()
    {
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public sha512digest(sha512digest t)
    {
        super(t);
    }

    public string getalgorithmname()
    {
        return "sha-512";
    }

    public int getdigestsize()
    {
        return digest_length;
    }

    public int dofinal(
        byte[]  out,
        int     outoff)
    {
        finish();

        pack.longtobigendian(h1, out, outoff);
        pack.longtobigendian(h2, out, outoff + 8);
        pack.longtobigendian(h3, out, outoff + 16);
        pack.longtobigendian(h4, out, outoff + 24);
        pack.longtobigendian(h5, out, outoff + 32);
        pack.longtobigendian(h6, out, outoff + 40);
        pack.longtobigendian(h7, out, outoff + 48);
        pack.longtobigendian(h8, out, outoff + 56);

        reset();

        return digest_length;
    }

    /**
     * reset the chaining variables
     */
    public void reset()
    {
        super.reset();

        /* sha-512 initial hash value
         * the first 64 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */
        h1 = 0x6a09e667f3bcc908l;
        h2 = 0xbb67ae8584caa73bl;
        h3 = 0x3c6ef372fe94f82bl;
        h4 = 0xa54ff53a5f1d36f1l;
        h5 = 0x510e527fade682d1l;
        h6 = 0x9b05688c2b3e6c1fl;
        h7 = 0x1f83d9abfb41bd6bl;
        h8 = 0x5be0cd19137e2179l;
    }

    public memoable copy()
    {
        return new sha512digest(this);
    }

    public void reset(memoable other)
    {
        sha512digest d = (sha512digest)other;

        copyin(d);
    }
}

