package org.ripple.bouncycastle.crypto;

/**
 * the basic interface for key encapsulation mechanisms.
 */
public interface keyencapsulation
{
    /**
     * initialise the key encapsulation mechanism.
     */
    public void init(cipherparameters param);

    /**
     * encapsulate a randomly generated session key.    
     */
    public cipherparameters encrypt(byte[] out, int outoff, int keylen);
    
    /**
     * decapsulate an encapsulated session key.
     */
    public cipherparameters decrypt(byte[] in, int inoff, int inlen, int keylen);
}
