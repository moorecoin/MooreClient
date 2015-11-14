package org.ripple.bouncycastle.crypto;

/**
 * generic signer interface for hash based and message recovery signers.
 */
public interface signer 
{
    /**
     * initialise the signer for signing or verification.
     * 
     * @param forsigning true if for signing, false otherwise
     * @param param necessary parameters.
     */
    public void init(boolean forsigning, cipherparameters param);

    /**
     * update the internal digest with the byte b
     */
    public void update(byte b);

    /**
     * update the internal digest with the byte array in
     */
    public void update(byte[] in, int off, int len);

    /**
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generatesignature()
        throws cryptoexception, datalengthexception;

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     */
    public boolean verifysignature(byte[] signature);
    
    /**
     * reset the internal state
     */
    public void reset();
}
