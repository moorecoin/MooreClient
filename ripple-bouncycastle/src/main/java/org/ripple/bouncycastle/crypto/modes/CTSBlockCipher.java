package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a cipher text stealing (cts) mode cipher. cts allows block ciphers to
 * be used to produce cipher text which is the same length as the plain text.
 */
public class ctsblockcipher
    extends bufferedblockcipher
{
    private int     blocksize;

    /**
     * create a buffered block cipher that uses cipher text stealing
     *
     * @param cipher the underlying block cipher this buffering object wraps.
     */
    public ctsblockcipher(
        blockcipher     cipher)
    {
        if ((cipher instanceof ofbblockcipher) || (cipher instanceof cfbblockcipher))
        {
            throw new illegalargumentexception("ctsblockcipher can only accept ecb, or cbc ciphers");
        }

        this.cipher = cipher;

        blocksize = cipher.getblocksize();

        buf = new byte[blocksize * 2];
        bufoff = 0;
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
        return len + bufoff;
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

        if (bufoff == buf.length)
        {
            resultlen = cipher.processblock(buf, 0, out, outoff);
            system.arraycopy(buf, blocksize, buf, 0, blocksize);

            bufoff = blocksize;
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
                throw new datalengthexception("output buffer too short");
            }
        }

        int resultlen = 0;
        int gaplen = buf.length - bufoff;

        if (len > gaplen)
        {
            system.arraycopy(in, inoff, buf, bufoff, gaplen);

            resultlen += cipher.processblock(buf, 0, out, outoff);
            system.arraycopy(buf, blocksize, buf, 0, blocksize);

            bufoff = blocksize;

            len -= gaplen;
            inoff += gaplen;

            while (len > blocksize)
            {
                system.arraycopy(in, inoff, buf, bufoff, blocksize);
                resultlen += cipher.processblock(buf, 0, out, outoff + resultlen);
                system.arraycopy(buf, blocksize, buf, 0, blocksize);

                len -= blocksize;
                inoff += blocksize;
            }
        }

        system.arraycopy(in, inoff, buf, bufoff, len);

        bufoff += len;

        return resultlen;
    }

    /**
     * process the last block in the buffer.
     *
     * @param out the array the block currently being held is copied into.
     * @param outoff the offset at which the copying starts.
     * @return the number of output bytes copied to out.
     * @exception datalengthexception if there is insufficient space in out for
     * the output.
     * @exception illegalstateexception if the underlying cipher is not
     * initialised.
     * @exception invalidciphertextexception if cipher text decrypts wrongly (in
     * case the exception will never get thrown).
     */
    public int dofinal(
        byte[]  out,
        int     outoff)
        throws datalengthexception, illegalstateexception, invalidciphertextexception
    {
        if (bufoff + outoff > out.length)
        {
            throw new datalengthexception("output buffer to small in dofinal");
        }

        int     blocksize = cipher.getblocksize();
        int     len = bufoff - blocksize;
        byte[]  block = new byte[blocksize];

        if (forencryption)
        {
            cipher.processblock(buf, 0, block, 0);
            
            if (bufoff < blocksize)
            {
                throw new datalengthexception("need at least one block of input for cts");
            }

            for (int i = bufoff; i != buf.length; i++)
            {
                buf[i] = block[i - blocksize];
            }

            for (int i = blocksize; i != bufoff; i++)
            {
                buf[i] ^= block[i - blocksize];
            }

            if (cipher instanceof cbcblockcipher)
            {
                blockcipher c = ((cbcblockcipher)cipher).getunderlyingcipher();

                c.processblock(buf, blocksize, out, outoff);
            }
            else
            {
                cipher.processblock(buf, blocksize, out, outoff);
            }

            system.arraycopy(block, 0, out, outoff + blocksize, len);
        }
        else
        {
            byte[]  lastblock = new byte[blocksize];

            if (cipher instanceof cbcblockcipher)
            {
                blockcipher c = ((cbcblockcipher)cipher).getunderlyingcipher();

                c.processblock(buf, 0, block, 0);
            }
            else
            {
                cipher.processblock(buf, 0, block, 0);
            }

            for (int i = blocksize; i != bufoff; i++)
            {
                lastblock[i - blocksize] = (byte)(block[i - blocksize] ^ buf[i]);
            }

            system.arraycopy(buf, blocksize, block, 0, len);

            cipher.processblock(block, 0, out, outoff);
            system.arraycopy(lastblock, 0, out, outoff + blocksize, len);
        }

        int offset = bufoff;

        reset();

        return offset;
    }
}
