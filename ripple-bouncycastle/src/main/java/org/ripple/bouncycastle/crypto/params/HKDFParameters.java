package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.derivationparameters;
import org.ripple.bouncycastle.util.arrays;

/**
 * parameter class for the hkdfbytesgenerator class.
 */
public class hkdfparameters
    implements derivationparameters
{
    private final byte[] ikm;
    private final boolean skipexpand;
    private final byte[] salt;
    private final byte[] info;

    private hkdfparameters(final byte[] ikm, final boolean skip,
                           final byte[] salt, final byte[] info)
    {
        if (ikm == null)
        {
            throw new illegalargumentexception(
                "ikm (input keying material) should not be null");
        }

        this.ikm = arrays.clone(ikm);

        this.skipexpand = skip;

        if (salt == null || salt.length == 0)
        {
            this.salt = null;
        }
        else
        {
            this.salt = arrays.clone(salt);
        }

        if (info == null)
        {
            this.info = new byte[0];
        }
        else
        {
            this.info = arrays.clone(info);
        }
    }

    /**
     * generates parameters for hkdf, specifying both the optional salt and
     * optional info. step 1: extract won't be skipped.
     *
     * @param ikm  the input keying material or seed
     * @param salt the salt to use, may be null for a salt for hashlen zeros
     * @param info the info to use, may be null for an info field of zero bytes
     */
    public hkdfparameters(final byte[] ikm, final byte[] salt, final byte[] info)
    {
        this(ikm, false, salt, info);
    }

    /**
     * factory method that makes the hkdf skip the extract part of the key
     * derivation function.
     *
     * @param ikm  the input keying material or seed, directly used for step 2:
     *             expand
     * @param info the info to use, may be null for an info field of zero bytes
     * @return hkdfparameters that makes the implementation skip step 1
     */
    public static hkdfparameters skipextractparameters(final byte[] ikm,
                                                       final byte[] info)
    {

        return new hkdfparameters(ikm, true, null, info);
    }

    public static hkdfparameters defaultparameters(final byte[] ikm)
    {
        return new hkdfparameters(ikm, false, null, null);
    }

    /**
     * returns the input keying material or seed.
     *
     * @return the keying material
     */
    public byte[] getikm()
    {
        return arrays.clone(ikm);
    }

    /**
     * returns if step 1: extract has to be skipped or not
     *
     * @return true for skipping, false for no skipping of step 1
     */
    public boolean skipextract()
    {
        return skipexpand;
    }

    /**
     * returns the salt, or null if the salt should be generated as a byte array
     * of hashlen zeros.
     *
     * @return the salt, or null
     */
    public byte[] getsalt()
    {
        return arrays.clone(salt);
    }

    /**
     * returns the info field, which may be empty (null is converted to empty).
     *
     * @return the info field, never null
     */
    public byte[] getinfo()
    {
        return arrays.clone(info);
    }
}
