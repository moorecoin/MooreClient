package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * implements the gost 28147 ofb counter mode (gctr).
 */
public class gofbblockcipher
    implements blockcipher
{
    private byte[]          iv;
    private byte[]          ofbv;
    private byte[]          ofboutv;

    private final int             blocksize;
    private final blockcipher     cipher;

    boolean firststep = true;
    int n3;
    int n4;
    static final int c1 = 16843012; //00000001000000010000000100000100
    static final int c2 = 16843009; //00000001000000010000000100000001


    /**
     * basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * counter mode (must have a 64 bit block size).
     */
    public gofbblockcipher(
        blockcipher cipher)
    {
        this.cipher = cipher;
        this.blocksize = cipher.getblocksize();
        
        if (blocksize != 8)
        {
            throw new illegalargumentexception("gctr only for 64 bit block ciphers");
        }

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
        boolean             encrypting, //ignored by this ctr mode
        cipherparameters    params)
        throws illegalargumentexception
    {
        firststep = true;
        n3 = 0;
        n4 = 0;

        if (params instanceof parameterswithiv)
        {
            parameterswithiv ivparam = (parameterswithiv)params;
            byte[] iv = ivparam.getiv();

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

            // if params is null we reuse the current working key.
            if (ivparam.getparameters() != null)
            {
                cipher.init(true, ivparam.getparameters());
            }
        }
        else
        {
            reset();

            // if params is null we reuse the current working key.
            if (params != null)
            {
                cipher.init(true, params);
            }
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/gctr"
     * and the block size in bits
     */
    public string getalgorithmname()
    {
        return cipher.getalgorithmname() + "/gctr";
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

        if (firststep)
        {
            firststep = false;
            cipher.processblock(ofbv, 0, ofboutv, 0);
            n3 = bytestoint(ofboutv, 0);
            n4 = bytestoint(ofboutv, 4);
        }
        n3 += c2;
        n4 += c1;
        inttobytes(n3, ofbv, 0);
        inttobytes(n4, ofbv, 4);

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

    //array of bytes to type int
    private int bytestoint(
        byte[]  in,
        int     inoff)
    {
        return  ((in[inoff + 3] << 24) & 0xff000000) + ((in[inoff + 2] << 16) & 0xff0000) +
                ((in[inoff + 1] << 8) & 0xff00) + (in[inoff] & 0xff);
    }

    //int to array of bytes
    private void inttobytes(
            int     num,
            byte[]  out,
            int     outoff)
    {
            out[outoff + 3] = (byte)(num >>> 24);
            out[outoff + 2] = (byte)(num >>> 16);
            out[outoff + 1] = (byte)(num >>> 8);
            out[outoff] =     (byte)num;
    }
}
