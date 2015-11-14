package org.ripple.bouncycastle.crypto;


/**
 * a wrapper class that allows block ciphers to be used to process data in
 * a piecemeal fashion. the bufferedblockcipher outputs a block only when the
 * buffer is full and more data is being added, or on a dofinal.
 * <p>
 * note: in the case where the underlying cipher is either a cfb cipher or an
 * ofb one the last block may not be a multiple of the block size.
 */
public class bufferedblockcipher
{
    protected byte[]        buf;
    protected int           bufoff;

    protected boolean       forencryption;
    protected blockcipher   cipher;

    protected boolean       partialblockokay;
    protected boolean       pgpcfb;

    /**
     * constructor for subclasses
     */
    protected bufferedblockcipher()
    {
    }

    /**
     * create a buffered block cipher without padding.
     *
     * @param cipher the underlying block cipher this buffering object wraps.
     */
    public bufferedblockcipher(
        blockcipher     cipher)
    {
        this.cipher = cipher;

        buf = new byte[cipher.getblocksize()];
        bufoff = 0;

        //
        // check if we can handle partial blocks on dofinal.
        //
        string  name = cipher.getalgorithmname();
        int     idx = name.indexof('/') + 1;

        pgpcfb = (idx > 0 && name.startswith("pgp", idx));

        if (pgpcfb)
        {
            partialblockokay = true;
        }
        else
        {
            partialblockokay = (idx > 0 && (name.startswith("cfb", idx) || name.startswith("ofb", idx) || name.startswith("openpgp", idx) || name.startswith("sic", idx) || name.startswith("gctr", idx)));
        }
    }

    /**
     * return the cipher this object wraps.
     *
     * @return the cipher this object wraps.
     */
    public blockcipher getunderlyingcipher()
    {
        return cipher;
    }

    /**
     * initialise the cipher.
     *
     * @param forencryption if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             forencryption,
        cipherparameters    params)
        throws illegalargumentexception
    {
        this.forencryption = forencryption;

        reset();

        cipher.init(forencryption, params);
    }

    /**
     * return the blocksize for the underlying cipher.
     *
     * @return the blocksize for the underlying cipher.
     */
    public int getblocksize()
    {
        return cipher.getblocksize();
    }

    /**
     * return the size of the output buffer required for an update 
     * an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to update
     * with len bytes of input.
     */
    public int getupdateoutputsize(
        int len)
    {
        int total       = len + bufoff;
        int leftover;

        if (pgpcfb)
        {
            leftover    = total % buf.length - (cipher.getblocksize() + 2);
        }
        else
        {
            leftover    = total % buf.length;
        }

        return total - leftover;
    }

    /**
     * return the size of the output buffer required for an update plus a
     * dofinal with an input of 'length' bytes.
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to update and dofinal
     * with 'length' bytes of input.
     */
    public int getoutputsize(
        int length)
    {
        // note: can assume partialblockokay is true for purposes of this calculation
        return length + bufoff;
    }

    /**
     * process a single byte, producing an output block if neccessary.
     *
     * @param in the input byte.
     * @param out the space for any output that might be produced.
     * @param outoff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception datalengthexception if there isn't enough space in out.
     * @exception illegalstateexception if the cipher isn't initialised.
     */
    public int processbyte(
        byte        in,
        byte[]      out,
        int         outoff)
        throws datalengthexception, illegalstateexception
    {
        int         resultlen = 0;

        buf[bufoff++] = in;

        if (bufoff == buf.length)
        {
            resultlen = cipher.processblock(buf, 0, out, outoff);
            bufoff = 0;
        }

        return resultlen;
    }

    /**
     * process an array of bytes, producing output if necessary.
     *
     * @param in the input byte array.
     * @param inoff the offset at which the input data starts.
     * @param len the number of bytes to be copied out of the input array.
     * @param out the space for any output that might be produced.
     * @param outoff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception datalengthexception if there isn't enough space in out.
     * @exception illegalstateexception if the cipher isn't initialised.
     */
    public int processbytes(
        byte[]      in,
        int         inoff,
        int         len,
        byte[]      out,
        int         outoff)
        throws datalengthexception, illegalstateexception
    {
        if (len < 0)
        {
            throw new illegalargumentexception("can't have a negative input length!");
        }

        int blocksize   = getblocksize();
        int length      = getupdateoutputsize(len);
        
        if (length > 0)
        {
            if ((outoff + length) > out.length)
            {
                throw new outputlengthexception("output buffer too short");
            }
        }

        int resultlen = 0;
        int gaplen = buf.length - bufoff;

        if (len > gaplen)
        {
            system.arraycopy(in, inoff, buf, bufoff, gaplen);

            resultlen += cipher.processblock(buf, 0, out, outoff);

            bufoff = 0;
            len -= gaplen;
            inoff += gaplen;

            while (len > buf.length)
            {
                resultlen += cipher.processblock(in, inoff, out, outoff + resultlen);

                len -= blocksize;
                inoff += blocksize;
            }
        }

        system.arraycopy(in, inoff, buf, bufoff, len);

        bufoff += len;

        if (bufoff == buf.length)
        {
            resultlen += cipher.processblock(buf, 0, out, outoff + resultlen);
            bufoff = 0;
        }

        return resultlen;
    }

    /**
     * process the last block in the buffer.
     *
     * @param out the array the block currently being held is copied into.
     * @param outoff the offset at which the copying starts.
     * @return the number of output bytes copied to out.
     * @exception datalengthexception if there is insufficient space in out for
     * the output, or the input is not block size aligned and should be.
     * @exception illegalstateexception if the underlying cipher is not
     * initialised.
     * @exception invalidciphertextexception if padding is expected and not found.
     * @exception datalengthexception if the input is not block size
     * aligned.
     */
    public int dofinal(
        byte[]  out,
        int     outoff)
        throws datalengthexception, illegalstateexception, invalidciphertextexception
    {
        try
        {
            int resultlen = 0;

            if (outoff + bufoff > out.length)
            {
                throw new outputlengthexception("output buffer too short for dofinal()");
            }

            if (bufoff != 0)
            {
                if (!partialblockokay)
                {
                    throw new datalengthexception("data not block size aligned");
                }

                cipher.processblock(buf, 0, buf, 0);
                resultlen = bufoff;
                bufoff = 0;
                system.arraycopy(buf, 0, out, outoff, resultlen);
            }

            return resultlen;
        }
        finally
        {
            reset();
        }
    }

    /**
     * reset the buffer and cipher. after resetting the object is in the same
     * state as it was after the last init (if there was one).
     */
    public void reset()
    {
        //
        // clean the buffer.
        //
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] = 0;
        }

        bufoff = 0;

        //
        // reset the underlying cipher.
        //
        cipher.reset();
    }
}
