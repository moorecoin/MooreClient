package org.ripple.bouncycastle.crypto;


/**
 * block cipher engines are expected to conform to this interface.
 */
public interface blockcipher
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
     * return the block size for this cipher (in bytes).
     *
     * @return the block size for this cipher in bytes.
     */
    public int getblocksize();

    /**
     * process one block of input from the array in and write it to
     * the out array.
     *
     * @param in the array containing the input data.
     * @param inoff offset into the in array the data starts at.
     * @param out the array the output data will be copied into.
     * @param outoff the offset into the out array the output will start at.
     * @exception datalengthexception if there isn't enough data in in, or
     * space in out.
     * @exception illegalstateexception if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    public int processblock(byte[] in, int inoff, byte[] out, int outoff)
        throws datalengthexception, illegalstateexception;

    /**
     * reset the cipher. after resetting the cipher is in the same state
     * as it was after the last init (if there was one).
     */
    public void reset();
}
