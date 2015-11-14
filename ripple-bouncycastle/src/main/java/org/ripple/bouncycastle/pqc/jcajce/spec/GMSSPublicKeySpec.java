package org.ripple.bouncycastle.pqc.jcajce.spec;

import org.ripple.bouncycastle.pqc.crypto.gmss.gmssparameters;

/**
 * this class provides a specification for a gmss public key.
 *
 * @see org.ripple.bouncycastle.pqc.jcajce.provider.gmss.bcgmsspublickey
 */
public class gmsspublickeyspec
    extends gmsskeyspec
{
    /**
     * the gmss public key
     */
    private byte[] gmsspublickey;

    /**
     * the constructor.
     *
     * @param key              a raw gmss public key
     * @param gmssparameterset an instance of gmssparameterset
     */
    public gmsspublickeyspec(byte[] key, gmssparameters gmssparameterset)
    {
        super(gmssparameterset);

        this.gmsspublickey = key;
    }

    /**
     * returns the gmss public key
     *
     * @return the gmss public key
     */
    public byte[] getpublickey()
    {
        return gmsspublickey;
    }
}
