package org.ripple.bouncycastle.crypto;

/**
 * a wrapper for block ciphers with a single byte block size, so that they
 * can be treated like stream ciphers.
 */
public class streamblockcipher
    implements streamcipher
{
    private blockcipher  cipher;

    private byte[]  onebyte = new byte[1];

    /**
     * basic constructor.
     *
     * @param cipher the block cipher to be wrapped.
     * @exception illegalargumentexception if the cipher has a block size other than
     * one.
     */
    public streamblockcipher(
        blockcipher cipher)
    {
        if (cipher.getblocksize() != 1)
        {
            throw new illegalargumentexception("block cipher block size != 1.");
        }

        this.cipher = cipher;
    }

    /**
     * initialise the underlying cipher.
     *
     * @param forencryption true if we are setting up for encryption, false otherwise.
     * @param params the necessary parameters for the underlying cipher to be initialised.
     */
    public void init(
        boolean forencryption,
        cipherparameters params)
    {
        cipher.init(forencryption, params);
    }

    /**
     * return the name of the algorithm we are wrapping.
     *
     * @return the name of the algorithm we are wrapping.
     */
    public string getalgorithmname()
    {
        return cipher.getalgorithmname();
    }

    /**
     * encrypt/decrypt a single byte returning the result.
     *
     * @param in the byte to be processed.
     * @return the result of processing the input byte.
     */
    public byte returnbyte(
        byte    in)
    {
        onebyte[0] = in;

        cipher.processblock(onebyte, 0, onebyte, 0);

        return onebyte[0];
    }

    /**
     * process a block of bytes from in putting the result into out.
     * 
     * @param in the input byte array.
     * @param inoff the offset into the in array where the data to be processed starts.
     * @param len the number of bytes to be processed.
     * @param out the output buffer the processed bytes go into.   
     * @param outoff the offset into the output byte array the processed data stars at.
     * @exception datalengthexception if the output buffer is too small.
     */
    public void processbytes(
        byte[]  in,
        int     inoff,
        int     len,
        byte[]  out,
        int     outoff)
        throws datalengthexception
    {
        if (outoff + len > out.length)
        {
            throw new datalengthexception("output buffer too small in processbytes()");
        }

        for (int i = 0; i != len; i++)
        {
                cipher.processblock(in, inoff + i, out, outoff + i);
        }
    }

    /**
     * reset the underlying cipher. this leaves it in the same state
     * it was at after the last init (if there was one).
     */
    public void reset()
    {
        cipher.reset();
    }
}
