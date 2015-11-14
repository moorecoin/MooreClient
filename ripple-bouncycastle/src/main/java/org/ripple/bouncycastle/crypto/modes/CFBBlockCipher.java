package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * implements a cipher-feedback (cfb) mode on top of a simple cipher.
 */
public class cfbblockcipher
    implements blockcipher
{
    private byte[]          iv;
    private byte[]          cfbv;
    private byte[]          cfboutv;

    private int             blocksize;
    private blockcipher     cipher = null;
    private boolean         encrypting;

    /**
     * basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     * @param bitblocksize the block size in bits (note: a multiple of 8)
     */
    public cfbblockcipher(
        blockcipher cipher,
        int         bitblocksize)
    {
        this.cipher = cipher;
        this.blocksize = bitblocksize / 8;

        this.iv = new byte[cipher.getblocksize()];
        this.cfbv = new byte[cipher.getblocksize()];
        this.cfboutv = new byte[cipher.getblocksize()];
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
        boolean             encrypting,
        cipherparameters    params)
        throws illegalargumentexception
    {
        this.encrypting = encrypting;
        
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
     * @return the name of the underlying algorithm followed by "/cfb"
     * and the block size in bits.
     */
    public string getalgorithmname()
    {
        return cipher.getalgorithmname() + "/cfb" + (blocksize * 8);
    }

    /**
     * return the block size we are operating at.
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
        return (encrypting) ? encryptblock(in, inoff, out, outoff) : decryptblock(in, inoff, out, outoff);
    }

    /**
     * do the appropriate processing for cfb mode encryption.
     *
     * @param in the array containing the data to be encrypted.
     * @param inoff offset into the in array the data starts at.
     * @param out the array the encrypted data will be copied into.
     * @param outoff the offset into the out array the output will start at.
     * @exception datalengthexception if there isn't enough data in in, or
     * space in out.
     * @exception illegalstateexception if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    public int encryptblock(
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

        cipher.processblock(cfbv, 0, cfboutv, 0);

        //
        // xor the cfbv with the plaintext producing the ciphertext
        //
        for (int i = 0; i < blocksize; i++)
        {
            out[outoff + i] = (byte)(cfboutv[i] ^ in[inoff + i]);
        }

        //
        // change over the input block.
        //
        system.arraycopy(cfbv, blocksize, cfbv, 0, cfbv.length - blocksize);
        system.arraycopy(out, outoff, cfbv, cfbv.length - blocksize, blocksize);

        return blocksize;
    }

    /**
     * do the appropriate processing for cfb mode decryption.
     *
     * @param in the array containing the data to be decrypted.
     * @param inoff offset into the in array the data starts at.
     * @param out the array the encrypted data will be copied into.
     * @param outoff the offset into the out array the output will start at.
     * @exception datalengthexception if there isn't enough data in in, or
     * space in out.
     * @exception illegalstateexception if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    public int decryptblock(
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

        cipher.processblock(cfbv, 0, cfboutv, 0);

        //
        // change over the input block.
        //
        system.arraycopy(cfbv, blocksize, cfbv, 0, cfbv.length - blocksize);
        system.arraycopy(in, inoff, cfbv, cfbv.length - blocksize, blocksize);

        //
        // xor the cfbv with the ciphertext producing the plaintext
        //
        for (int i = 0; i < blocksize; i++)
        {
            out[outoff + i] = (byte)(cfboutv[i] ^ in[inoff + i]);
        }

        return blocksize;
    }

    /**
     * reset the chaining vector back to the iv and reset the underlying
     * cipher.
     */
    public void reset()
    {
        system.arraycopy(iv, 0, cfbv, 0, iv.length);

        cipher.reset();
    }
}
