package org.ripple.bouncycastle.pqc.crypto.gmss;


public class gmsspublickeyparameters
    extends gmsskeyparameters
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
    public gmsspublickeyparameters(byte[] key, gmssparameters gmssparameterset)
    {
        super(false, gmssparameterset);
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
