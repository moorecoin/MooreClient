package org.ripple.bouncycastle.crypto.digests;

import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.memoable;


/**
 * fips 180-2 implementation of sha-384.
 *
 * <pre>
 *         block  word  digest
 * sha-1   512    32    160
 * sha-256 512    32    256
 * sha-384 1024   64    384
 * sha-512 1024   64    512
 * </pre>
 */
public class sha384digest
    extends longdigest
{
    private static final int    digest_length = 48;

    /**
     * standard constructor
     */
    public sha384digest()
    {
    }

    /**
     * copy constructor.  this will copy the state of the provided
     * message digest.
     */
    public sha384digest(sha384digest t)
    {
        super(t);
    }

    public string getalgorithmname()
    {
        return "sha-384";
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

        reset();

        return digest_length;
    }

    /**
     * reset the chaining variables
     */
    public void reset()
    {
        super.reset();

        /* sha-384 initial hash value
         * the first 64 bits of the fractional parts of the square roots
         * of the 9th through 16th prime numbers
         */
        h1 = 0xcbbb9d5dc1059ed8l;
        h2 = 0x629a292a367cd507l;
        h3 = 0x9159015a3070dd17l;
        h4 = 0x152fecd8f70e5939l;
        h5 = 0x67332667ffc00b31l;
        h6 = 0x8eb44a8768581511l;
        h7 = 0xdb0c2e0d64f98fa7l;
        h8 = 0x47b5481dbefa4fa4l;
    }

    public memoable copy()
    {
        return new sha384digest(this);
    }

    public void reset(memoable other)
    {
        sha384digest d = (sha384digest)other;

        super.copyin(d);
    }
}
