package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.digest;

/**
 * kdf1 generator for derived keys and ivs as defined by ieee p1363a/iso 18033
 * <br>
 * this implementation is based on iso 18033/ieee p1363a.
 */
public class kdf1bytesgenerator
    extends basekdfbytesgenerator
{
    /**
     * construct a kdf1 byte generator.
     * <p>
     * @param digest the digest to be used as the source of derived keys.
     */
    public kdf1bytesgenerator(
        digest  digest)
    {
        super(0, digest);
    }
}
