package org.ripple.bouncycastle.bcpg;

/**
 * base interface for a pgp key
 */
public interface bcpgkey
{
    /**
     * return the base format for this key - in the case of the symmetric keys it will generally
     * be raw indicating that the key is just a straight byte representation, for an asymmetric
     * key the format will be pgp, indicating the key is a string of mpis encoded in pgp format.
     * 
     * @return "raw" or "pgp"
     */
    public string getformat();
    
    /**
     * return a string of bytes giving the encoded format of the key, as described by it's format.
     * 
     * @return byte[]
     */
    public byte[] getencoded();
    
}
