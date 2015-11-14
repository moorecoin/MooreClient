package org.ripple.bouncycastle.crypto;

/**
 * interface that a message digest conforms to.
 */
public interface digest
{
    /**
     * return the algorithm name
     *
     * @return the algorithm name
     */
    public string getalgorithmname();

    /**
     * return the size, in bytes, of the digest produced by this message digest.
     *
     * @return the size, in bytes, of the digest produced by this message digest.
     */
    public int getdigestsize();

    /**
     * update the message digest with a single byte.
     *
     * @param in the input byte to be entered.
     */
    public void update(byte in);

    /**
     * update the message digest with a block of bytes.
     *
     * @param in the byte array containing the data.
     * @param inoff the offset into the byte array where the data starts.
     * @param len the length of the data.
     */
    public void update(byte[] in, int inoff, int len);

    /**
     * close the digest, producing the final digest value. the dofinal
     * call leaves the digest reset.
     *
     * @param out the array the digest is to be copied into.
     * @param outoff the offset into the out array the digest is to start at.
     */
    public int dofinal(byte[] out, int outoff);

    /**
     * reset the digest back to it's initial state.
     */
    public void reset();
}
