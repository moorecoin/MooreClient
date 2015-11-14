package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * implements a output-feedback (ofb) mode on top of a simple cipher.
 */
public class ofbblockcipher
    implements blockcipher
{
    private byte[]          iv;
    private byte[]          ofbv;
    private byte[]          ofboutv;

    private final int             blocksize;
    private final blockcipher     cipher;

    /**
     * basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     * @param blocksize the block size in bits (note: a multiple of 8)
     */
    public ofbblockcipher(
        blockcipher cipher,
        int         blocksize)
    {
        this.cipher = cipher;
        this.blocksize = blocksize / 8;

        this.iv = new byte[cipher.getblocksize()];
        this.ofbv = new byte[cipher.getblocksize()];
        this.ofboutv = new byte[cipher.getblocksize()];
    }

    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    public blockcipher getunderlyingcipher()
    {
        return cipher;
    }

    /**
     * initialise the cipher and, possibly, the initialisation vector (iv).
     * if an iv isn't passed as part of the parameter, the iv will be all zeros.
     * an iv which is too short is handled in fips compliant fashion.
     *
     * @param encrypting if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             encrypting, //ignored by this ofb mode
        cipherparameters    params)
        throws illegalargumentexception
    {
        if (params instanceof parameterswithiv)
        {
            parameterswithiv ivparam = (parameterswithiv)params;
            byte[]      iv = ivparam.getiv();

            if (iv.length < iv.length)
            {
                // prepend the supplied iv with zeros (per fips pub 81)
                system.arraycopy(iv, 0, iv, iv.length - iv.length, iv.length); 
                for (int i = 0; i < iv.length - iv.length; i++)
                {
                    iv[i] = 0;
                }
            }
            else
            {
                system.arraycopy(iv, 0, iv, 0, iv.length);
            }

            reset();

            // if null it's an iv changed only.
            if (ivparam.getparameters() != null)
            {
                cipher.init(true, ivparam.getparameters());
            }
        }
        else
        {
            reset();

            // if it's null, key is to be reused.
            if (params != null)
            {
                cipher.init(true, params);
            }
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/ofb"
     * and the block size in bits
     */
    public string getalgorithmname()
    {
        return cipher.getalgorithmname() + "/ofb" + (blocksize * 8);
    }

    
    /**
     * return the block size we are operating at (in bytes).
     *
     * @return the block size we are operating at (in bytes).
     */
    public int getblocksize()
    {
        return blocksize;
    }

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
    public int processblock(
        byte[]      in,
        int         inoff,
        byte[]      out,
        int         outoff)
        throws datalengthexception, illegalstateexception
    {
        if ((inoff + blocksize) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        if ((outoff + blocksize) > out.length)
        {
            throw new datalengthexception("output buffer too short");
        }

        cipher.processblock(ofbv, 0, ofboutv, 0);

        //
        // xor the ofbv with the plaintext producing the cipher text (and
        // the next input block).
        //
        for (int i = 0; i < blocksize; i++)
        {
            out[outoff + i] = (byte)(ofboutv[i] ^ in[inoff + i]);
        }

        //
        // change over the input block.
        //
        system.arraycopy(ofbv, blocksize, ofbv, 0, ofbv.length - blocksize);
        system.arraycopy(ofboutv, 0, ofbv, ofbv.length - blocksize, blocksize);

        return blocksize;
    }

    /**
     * reset the feedback vector back to the iv and reset the underlying
     * cipher.
     */
    public void reset()
    {
        system.arraycopy(iv, 0, ofbv, 0, iv.length);

        cipher.reset();
    }
}
