package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a wrapper class that allows block ciphers to be used to process data in
 * a piecemeal fashion with pkcs5/pkcs7 padding. the paddedblockcipher
 * outputs a block only when the buffer is full and more data is being added,
 * or on a dofinal (unless the current block in the buffer is a pad block).
 * the padding mechanism used is the one outlined in pkcs5/pkcs7.
 *
 * @deprecated use org.bouncycastle.crypto.paddings.paddedbufferedblockcipher instead.
 */
public class paddedblockcipher
    extends bufferedblockcipher
{
    /**
     * create a buffered block cipher with, or without, padding.
     *
     * @param cipher the underlying block cipher this buffering object wraps.
     */
    public paddedblockcipher(
        blockcipher     cipher)
    {
        this.cipher = cipher;

        buf = new byte[cipher.getblocksize()];
        bufoff = 0;
    }

    /**
     * return the size of the output buffer required for an update plus a
     * dofinal with an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to update and dofinal
     * with len bytes of input.
     */
    public int getoutputsize(
        int len)
    {
        int total       = len + bufoff;
        int leftover    = total % buf.length;

        if (leftover == 0)
        {
            if (forencryption)
            {
                return total + buf.length;
            }

            return total;
        }

        return total - leftover + buf.length;
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
        int leftover    = total % buf.length;

        if (leftover == 0)
        {
            return total - buf.length;
        }

        return total - leftover;
    }

    /**
     * process a single byte, producing an output block if neccessary.
     *
     * @param in the input byte.
     * @param out the space for any output that might be produced.
     * @param outoff the offset from which the output will be copied.
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

        if (bufoff == buf.length)
        {
            resultlen = cipher.processblock(buf, 0, out, outoff);
            bufoff = 0;
        }

        buf[bufoff++] = in;

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
                throw new datalengthexception("output buffer too short");
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

        return resultlen;
    }

    /**
     * process the last block in the buffer. if the buffer is currently
     * full and padding needs to be added a call to dofinal will produce
     * 2 * getblocksize() bytes.
     *
     * @param out the array the block currently being held is copied into.
     * @param outoff the offset at which the copying starts.
     * @exception datalengthexception if there is insufficient space in out for
     * the output or we are decrypting and the input is not block size aligned.
     * @exception illegalstateexception if the underlying cipher is not
     * initialised.
     * @exception invalidciphertextexception if padding is expected and not found.
     */
    public int dofinal(
        byte[]  out,
        int     outoff)
        throws datalengthexception, illegalstateexception, invalidciphertextexception
    {
        int blocksize = cipher.getblocksize();
        int resultlen = 0;

        if (forencryption)
        {
            if (bufoff == blocksize)
            {
                if ((outoff + 2 * blocksize) > out.length)
                {
                    throw new datalengthexception("output buffer too short");
                }

                resultlen = cipher.processblock(buf, 0, out, outoff);
                bufoff = 0;
            }

            //
            // add pkcs7 padding
            //
            byte code = (byte)(blocksize - bufoff);

            while (bufoff < blocksize)
            {
                buf[bufoff] = code;
                bufoff++;
            }

            resultlen += cipher.processblock(buf, 0, out, outoff + resultlen);
        }
        else
        {
            if (bufoff == blocksize)
            {
                resultlen = cipher.processblock(buf, 0, buf, 0);
                bufoff = 0;
            }
            else
            {
                throw new datalengthexception("last block incomplete in decryption");
            }

            //
            // remove pkcs7 padding
            //
            int count = buf[blocksize - 1] & 0xff;

            if ((count < 0) || (count > blocksize))
            {
                throw new invalidciphertextexception("pad block corrupted");
            }

            resultlen -= count;

            system.arraycopy(buf, 0, out, outoff, resultlen);
        }

        reset();

        return resultlen;
    }
}
