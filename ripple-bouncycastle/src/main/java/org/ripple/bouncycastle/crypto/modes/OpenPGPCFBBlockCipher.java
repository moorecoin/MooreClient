package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;

/**
 * implements openpgp's rather strange version of cipher-feedback (cfb) mode
 * on top of a simple cipher. this class assumes the iv has been prepended
 * to the data stream already, and just accomodates the reset after
 * (blocksize + 2) bytes have been read.
 * <p>
 * for further info see <a href="http://www.ietf.org/rfc/rfc2440.html">rfc 2440</a>.
 */
public class openpgpcfbblockcipher
    implements blockcipher
{
    private byte[] iv;
    private byte[] fr;
    private byte[] fre;

    private blockcipher cipher;

    private int count;
    private int blocksize;
    private boolean forencryption;
    
    /**
     * basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     */
    public openpgpcfbblockcipher(
        blockcipher cipher)
    {
        this.cipher = cipher;

        this.blocksize = cipher.getblocksize();
        this.iv = new byte[blocksize];
        this.fr = new byte[blocksize];
        this.fre = new byte[blocksize];
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
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/pgpcfb"
     * and the block size in bits.
     */
    public string getalgorithmname()
    {
        return cipher.getalgorithmname() + "/openpgpcfb";
    }
    
    /**
     * return the block size we are operating at.
     *
     * @return the block size we are operating at (in bytes).
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
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
        throws datalengthexception, illegalstateexception
    {
        return (forencryption) ? encryptblock(in, inoff, out, outoff) : decryptblock(in, inoff, out, outoff);
    }
    
    /**
     * reset the chaining vector back to the iv and reset the underlying
     * cipher.
     */
    public void reset()
    {
        count = 0;

        system.arraycopy(iv, 0, fr, 0, fr.length);

        cipher.reset();
    }

    /**
     * initialise the cipher and, possibly, the initialisation vector (iv).
     * if an iv isn't passed as part of the parameter, the iv will be all zeros.
     * an iv which is too short is handled in fips compliant fashion.
     *
     * @param forencryption if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        boolean forencryption,
        cipherparameters params)
        throws illegalargumentexception
    {
        this.forencryption = forencryption;
     
        reset();

        cipher.init(true, params);
    }
    
    /**
     * encrypt one byte of data according to cfb mode.
     * @param data the byte to encrypt
     * @param blockoff offset in the current block
     * @return the encrypted byte
     */
    private byte encryptbyte(byte data, int blockoff)
    {
        return (byte)(fre[blockoff] ^ data);
    }
    
    /**
     * do the appropriate processing for cfb iv mode encryption.
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
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
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
        
        if (count > blocksize)
        {
            fr[blocksize - 2] = out[outoff] = encryptbyte(in[inoff], blocksize - 2);
            fr[blocksize - 1] = out[outoff + 1] = encryptbyte(in[inoff + 1], blocksize - 1);

            cipher.processblock(fr, 0, fre, 0);

            for (int n = 2; n < blocksize; n++) 
            {
                fr[n - 2] = out[outoff + n] = encryptbyte(in[inoff + n], n - 2);
            }
        }
        else if (count == 0)
        {
            cipher.processblock(fr, 0, fre, 0);

            for (int n = 0; n < blocksize; n++) 
            {
                fr[n] = out[outoff + n] = encryptbyte(in[inoff + n], n);
            }
            
            count += blocksize;
        }
        else if (count == blocksize)
        {
            cipher.processblock(fr, 0, fre, 0);

            out[outoff] = encryptbyte(in[inoff], 0);
            out[outoff + 1] = encryptbyte(in[inoff + 1], 1);

            //
            // do reset
            //
            system.arraycopy(fr, 2, fr, 0, blocksize - 2);
            system.arraycopy(out, outoff, fr, blocksize - 2, 2);

            cipher.processblock(fr, 0, fre, 0);

            for (int n = 2; n < blocksize; n++) 
            {
                fr[n - 2] = out[outoff + n] = encryptbyte(in[inoff + n], n - 2);
            }

            count += blocksize;
        }
        
        return blocksize;
    }

    /**
     * do the appropriate processing for cfb iv mode decryption.
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
    private int decryptblock(
        byte[] in,
        int inoff,
        byte[] out,
        int outoff)
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
        
        if (count > blocksize)
        {
            byte inval = in[inoff];
            fr[blocksize - 2] = inval;
            out[outoff] = encryptbyte(inval, blocksize - 2);

            inval = in[inoff + 1];
            fr[blocksize - 1] = inval;
            out[outoff + 1] = encryptbyte(inval, blocksize - 1);

            cipher.processblock(fr, 0, fre, 0);
            
            for (int n = 2; n < blocksize; n++) 
            {
                inval = in[inoff + n];
                fr[n - 2] = inval;
                out[outoff + n] = encryptbyte(inval, n - 2);
            }
        } 
        else if (count == 0)
        {
            cipher.processblock(fr, 0, fre, 0);
            
            for (int n = 0; n < blocksize; n++) 
            {
                fr[n] = in[inoff + n];
                out[n] = encryptbyte(in[inoff + n], n);
            }
            
            count += blocksize;
        }
        else if (count == blocksize)
        {
            cipher.processblock(fr, 0, fre, 0);

            byte inval1 = in[inoff];
            byte inval2 = in[inoff + 1];
            out[outoff    ] = encryptbyte(inval1, 0);
            out[outoff + 1] = encryptbyte(inval2, 1);
            
            system.arraycopy(fr, 2, fr, 0, blocksize - 2);

            fr[blocksize - 2] = inval1;
            fr[blocksize - 1] = inval2;

            cipher.processblock(fr, 0, fre, 0);

            for (int n = 2; n < blocksize; n++) 
            {
                byte inval = in[inoff + n];
                fr[n - 2] = inval;
                out[outoff + n] = encryptbyte(inval, n - 2);
            }

            count += blocksize;
        }
        
        return blocksize;
    }
}
