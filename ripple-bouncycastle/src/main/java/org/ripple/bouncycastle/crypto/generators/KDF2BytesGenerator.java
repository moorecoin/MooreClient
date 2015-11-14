package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.digest;

/**
 * kdf2 generator for derived keys and ivs as defined by ieee p1363a/iso 18033
 * <br>
 * this implementation is based on ieee p1363/iso 18033.
 */
public class kdf2bytesgenerator
    extends basekdfbytesgenerator
{
    /**
     * construct a kdf2 bytes generator. generates key material
     * according to ieee p1363 or iso 18033 depending on the initialisation.
     * <p>
     * @param digest the digest to be used as the source of derived keys.
     */
    public kdf2bytesgenerator(
        digest  digest)
    {
        super(1, digest);
    }
}
