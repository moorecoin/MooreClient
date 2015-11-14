package org.ripple.bouncycastle.crypto;

/**
 * the interface stream ciphers conform to.
 */
public interface streamcipher
{
    /**
     * initialise the cipher.
     *
     * @param forencryption if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(boolean forencryption, cipherparameters params)
        throws illegalargumentexception;

    /**
     * return the name of the algorithm the cipher implements.
     *
     * @return the name of the algorithm the cipher implements.
     */
    public string getalgorithmname();

    /**
     * encrypt/decrypt a single byte returning the result.
     *
     * @param in the byte to be processed.
     * @return the result of processing the input byte.
     */
    public byte returnbyte(byte in);

    /**
     * process a block of bytes from in putting the result into out.
     *
     * @param in the input byte array.
     * @param inoff the offset into the in array where the data to be processed starts.
     * @param len the number of bytes to be processed.
     * @param out the output buffer the processed bytes go into.
     * @param outoff the offset into the output byte array the processed data starts at.
     * @exception datalengthexception if the output buffer is too small.
     */
    public void processbytes(byte[] in, int inoff, int len, byte[] out, int outoff)
        throws datalengthexception;

    /**
     * reset the cipher. this leaves it in the same state
     * it was at after the last init (if there was one).
     */
    public void reset();
}
