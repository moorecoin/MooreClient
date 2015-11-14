package org.ripple.bouncycastle.crypto;


/**
 * base interface that a public/private key block cipher needs
 * to conform to.
 */
public interface asymmetricblockcipher
{
    /**
     * initialise the cipher.
     *
     * @param forencryption if true the cipher is initialised for 
     *  encryption, if false for decryption.
     * @param param the key and other data required by the cipher.
     */
    public void init(boolean forencryption, cipherparameters param);

    /**
     * returns the largest size an input block can be.
     *
     * @return maximum size for an input block.
     */
    public int getinputblocksize();

    /**
     * returns the maximum size of the block produced by this cipher.
     *
     * @return maximum size of the output block produced by the cipher.
     */
    public int getoutputblocksize();

    /**
     * process the block of len bytes stored in in from offset inoff.
     *
     * @param in the input data
     * @param inoff offset into the in array where the data starts
     * @param len the length of the block to be processed.
     * @return the resulting byte array of the encryption/decryption process.
     * @exception invalidciphertextexception data decrypts improperly.
     * @exception datalengthexception the input data is too large for the cipher.
     */
    public byte[] processblock(byte[] in, int inoff, int len)
        throws invalidciphertextexception;
}
