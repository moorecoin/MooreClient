package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.util.arrays;

/**
 * implements cipher-block-chaining (cbc) mode on top of a simple cipher.
 */
public class cbcblockcipher
    implements blockcipher
{
    private byte[]          iv;
    private byte[]          cbcv;
    private byte[]          cbcnextv;

    private int             blocksize;
    private blockcipher     cipher = null;
    private boolean         encrypting;

    /**
     * basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of chaining.
     */
    public cbcblockcipher(
        blockcipher cipher)
    {
        this.cipher = cipher;
        this.blocksize = cipher.getblocksize();

        this.iv = new byte[blocksize];
        this.cbcv = new byte[blocksize];
        this.cbcnextv = new byte[blocksize];
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
        boolean oldencrypting = this.encrypting;

        this.encrypting = encrypting;

        if (params instanceof parameterswithiv)
        {
            parameterswithiv ivparam = (parameterswithiv)params;
            byte[] iv = ivparam.getiv();

            if (iv.length != blocksize)
            {
                throw new illegalargumentexception("initialisation vector must be the same length as block size");
            }

            system.arraycopy(iv, 0, iv, 0, iv.length);

            reset();

            // if null it's an iv changed only.
            if (ivparam.getparameters() != null)
            {
                cipher.init(encrypting, ivparam.getparameters());
            }
            else if (oldencrypting != encrypting)
            {
                throw new illegalargumentexception("cannot change encrypting state without providing key.");
            }
        }
        else
        {
            reset();

            // if it's null, key is to be reused.
            if (params != null)
            {
                cipher.init(encrypting, params);
            }
            else if (oldencrypting != encrypting)
            {
                throw new illegalargumentexception("cannot change encrypting state without providing key.");
            }
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/cbc".
     */
    public string getalgorithmname()
    {
        return cipher.getalgorithmname() + "/cbc";
    }

    /**
     * return the block size of the underlying cipher.
     *
     * @return the block size of the underlying cipher.
     */
    public int getblocksize()
    {
        return cipher.getblocksize();
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
     * reset the chaining vector back to the iv and reset the underlying
     * cipher.
     */
    public void reset()
    {
        system.arraycopy(iv, 0, cbcv, 0, iv.length);
        arrays.fill(cbcnextv, (byte)0);

        cipher.reset();
    }

    /**
     * do the appropriate chaining step for cbc mode encryption.
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
    private int encryptblock(
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

        /*
         * xor the cbcv and the input,
         * then encrypt the cbcv
         */
        for (int i = 0; i < blocksize; i++)
        {
            cbcv[i] ^= in[inoff + i];
        }

        int length = cipher.processblock(cbcv, 0, out, outoff);

        /*
         * copy ciphertext to cbcv
         */
        system.arraycopy(out, outoff, cbcv, 0, cbcv.length);

        return length;
    }

    /**
     * do the appropriate chaining step for cbc mode decryption.
     *
     * @param in the array containing the data to be decrypted.
     * @param inoff offset into the in array the data starts at.
     * @param out the array the decrypted data will be copied into.
     * @param outoff the offset into the out array the output will start at.
     * @exception datalengthexception if there isn't enough data in in, or
     * space in out.
     * @exception illegalstateexception if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    private int decryptblock(
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

        system.arraycopy(in, inoff, cbcnextv, 0, blocksize);

        int length = cipher.processblock(in, inoff, out, outoff);

        /*
         * xor the cbcv and the output
         */
        for (int i = 0; i < blocksize; i++)
        {
            out[outoff + i] ^= cbcv[i];
        }

        /*
         * swap the back up buffer into next position
         */
        byte[]  tmp;

        tmp = cbcv;
        cbcv = cbcnextv;
        cbcnextv = tmp;

        return length;
    }
}
