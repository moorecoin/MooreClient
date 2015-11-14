package org.ripple.bouncycastle.crypto;


/**
 * the base interface for implementations of message authentication codes (macs).
 */
public interface mac
{
    /**
     * initialise the mac.
     *
     * @param params the key and other data required by the mac.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(cipherparameters params)
        throws illegalargumentexception;

    /**
     * return the name of the algorithm the mac implements.
     *
     * @return the name of the algorithm the mac implements.
     */
    public string getalgorithmname();

    /**
     * return the block size for this mac (in bytes).
     *
     * @return the block size for this mac in bytes.
     */
    public int getmacsize();

    /**
     * add a single byte to the mac for processing.
     *
     * @param in the byte to be processed.
     * @exception illegalstateexception if the mac is not initialised.
     */
    public void update(byte in)
        throws illegalstateexception;

    /**
     * @param in the array containing the input.
     * @param inoff the index in the array the data begins at.
     * @param len the length of the input starting at inoff.
     * @exception illegalstateexception if the mac is not initialised.
     * @exception datalengthexception if there isn't enough data in in.
     */
    public void update(byte[] in, int inoff, int len)
        throws datalengthexception, illegalstateexception;

    /**
     * compute the final stage of the mac writing the output to the out
     * parameter.
     * <p>
     * dofinal leaves the mac in the same state it was after the last init.
     *
     * @param out the array the mac is to be output to.
     * @param outoff the offset into the out buffer the output is to start at.
     * @exception datalengthexception if there isn't enough space in out.
     * @exception illegalstateexception if the mac is not initialised.
     */
    public int dofinal(byte[] out, int outoff)
        throws datalengthexception, illegalstateexception;

    /**
     * reset the mac. at the end of resetting the mac should be in the
     * in the same state it was after the last init (if there was one).
     */
    public void reset();
}
