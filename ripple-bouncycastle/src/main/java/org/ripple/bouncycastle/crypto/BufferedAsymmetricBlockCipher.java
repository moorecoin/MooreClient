package org.ripple.bouncycastle.crypto;

/**
 * a buffer wrapper for an asymmetric block cipher, allowing input
 * to be accumulated in a piecemeal fashion until final processing.
 */
public class bufferedasymmetricblockcipher
{
    protected byte[]        buf;
    protected int           bufoff;

    private final asymmetricblockcipher   cipher;

    /**
     * base constructor.
     *
     * @param cipher the cipher this buffering object wraps.
     */
    public bufferedasymmetricblockcipher(
        asymmetricblockcipher     cipher)
    {
        this.cipher = cipher;
    }

    /**
     * return the underlying cipher for the buffer.
     *
     * @return the underlying cipher for the buffer.
     */
    public asymmetricblockcipher getunderlyingcipher()
    {
        return cipher;
    }

    /**
     * return the amount of data sitting in the buffer.
     *
     * @return the amount of data sitting in the buffer.
     */
    public int getbufferposition()
    {
        return bufoff;
    }

    /**
     * initialise the buffer and the underlying cipher.
     *
     * @param forencryption if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     */
    public void init(
        boolean             forencryption,
        cipherparameters    params)
    {
        reset();

        cipher.init(forencryption, params);

        //
        // we allow for an extra byte where people are using their own padding
        // mechanisms on a raw cipher.
        //
        buf = new byte[cipher.getinputblocksize() + (forencryption ? 1 : 0)];
        bufoff = 0;
    }

    /**
     * returns the largest size an input block can be.
     *
     * @return maximum size for an input block.
     */
    public int getinputblocksize()
    {
        return cipher.getinputblocksize();
    }

    /**
     * returns the maximum size of the block produced by this cipher.
     *
     * @return maximum size of the output block produced by the cipher.
     */
    public int getoutputblocksize()
    {
        return cipher.getoutputblocksize();
    }

    /**
     * add another byte for processing.
     * 
     * @param in the input byte.
     */
    public void processbyte(
        byte        in)
    {
        if (bufoff >= buf.length)
        {
            throw new datalengthexception("attempt to process message too long for cipher");
        }

        buf[bufoff++] = in;
    }

    /**
     * add len bytes to the buffer for processing.
     *
     * @param in the input data
     * @param inoff offset into the in array where the data starts
     * @param len the length of the block to be processed.
     */
    public void processbytes(
        byte[]      in,
        int         inoff,
        int         len)
    {
        if (len == 0)
        {
            return;
        }

        if (len < 0)
        {
            throw new illegalargumentexception("can't have a negative input length!");
        }

        if (bufoff + len > buf.length)
        {
            throw new datalengthexception("attempt to process message too long for cipher");
        }

        system.arraycopy(in, inoff, buf, bufoff, len);
        bufoff += len;
    }

    /**
     * process the contents of the buffer using the underlying
     * cipher.
     *
     * @return the result of the encryption/decryption process on the
     * buffer.
     * @exception invalidciphertextexception if we are given a garbage block.
     */
    public byte[] dofinal()
        throws invalidciphertextexception
    {
        byte[] out = cipher.processblock(buf, 0, bufoff);

        reset();

        return out;
    }

    /**
     * reset the buffer and the underlying cipher.
     */
    public void reset()
    {
        /*
         * clean the buffer.
         */
        if (buf != null)
        {
            for (int i = 0; i < buf.length; i++)
            {
                buf[i] = 0;
            }
        }

        bufoff = 0;
    }
}
