package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * implements openpgp's rather strange version of cipher-feedback (cfb) mode on top of a simple cipher. for further info see <a href="http://www.ietf.org/rfc/rfc2440.html">rfc 2440</a>.
 */
public class pgpcfbblockcipher
    implements blockcipher
{
    private byte[] iv;
    private byte[] fr;
    private byte[] fre;
    private byte[] tmp;

    private blockcipher cipher;

    private int count;
    private int blocksize;
    private boolean forencryption;
    
    private boolean inlineiv; // if false we don't need to prepend an iv

    /**
     * basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     * @param inlineiv if true this is for pgp cfb with a prepended iv.
     */
    public pgpcfbblockcipher(
        blockcipher cipher,
        boolean     inlineiv)
    {
        this.cipher = cipher;
        this.inlineiv = inlineiv;

        this.blocksize = cipher.getblocksize();
        this.iv = new byte[blocksize];
        this.fr = new byte[blocksize];
        this.fre = new byte[blocksize];
        this.tmp = new byte[blocksize];
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
        if (inlineiv)
        {
            return cipher.getalgorithmname() + "/pgpcfbwithiv";
        }
        else
        {
            return cipher.getalgorithmname() + "/pgpcfb";
        }
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
        if (inlineiv)
        {
            return (forencryption) ? encryptblockwithiv(in, inoff, out, outoff) : decryptblockwithiv(in, inoff, out, outoff);
        }
        else
        {
            return (forencryption) ? encryptblock(in, inoff, out, outoff) : decryptblock(in, inoff, out, outoff);
        }
    }
    
    /**
     * reset the chaining vector back to the iv and reset the underlying
     * cipher.
     */
    public void reset()
    {
        count = 0;

        for (int i = 0; i != fr.length; i++)
        {
            if (inlineiv)
            {
                fr[i] = 0;
            }
            else
            {
                fr[i] = iv[i]; // if simple mode, key is iv (even if this is zero)
            }
        }

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

                cipher.init(true, ivparam.getparameters());
        }
        else
        {
                reset();

                cipher.init(true, params);
        }
    }
    
    /**
     * encrypt one byte of data according to cfb mode.
     * @param data the byte to encrypt
     * @param blockoff where am i in the current block, determines when to resync the block
     * @returns the encrypted byte
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
    private int encryptblockwithiv(
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
        
        if (count == 0)
        {
            cipher.processblock(fr, 0, fre, 0);

            for (int n = 0; n < blocksize; n++) 
            {
                out[outoff + n] = encryptbyte(iv[n], n);
            }
            
            system.arraycopy(out, outoff, fr, 0, blocksize);

            cipher.processblock(fr, 0, fre, 0);

            out[outoff + blocksize] = encryptbyte(iv[blocksize - 2], 0);
            out[outoff + blocksize + 1] = encryptbyte(iv[blocksize - 1], 1);

            system.arraycopy(out, outoff + 2, fr, 0, blocksize);
            
            cipher.processblock(fr, 0, fre, 0);

            for (int n = 0; n < blocksize; n++) 
            {
                out[outoff + blocksize + 2 + n] = encryptbyte(in[inoff + n], n);
            }

            system.arraycopy(out, outoff + blocksize + 2, fr, 0, blocksize);

            count += 2 * blocksize + 2;

            return 2 * blocksize + 2;
        }
        else if (count >= blocksize + 2)
        {
            cipher.processblock(fr, 0, fre, 0);

            for (int n = 0; n < blocksize; n++) 
            {
                out[outoff + n] = encryptbyte(in[inoff + n], n);
            }
            
            system.arraycopy(out, outoff, fr, 0, blocksize);
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
    private int decryptblockwithiv(
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
        
        if (count == 0)
        {
            for (int n = 0; n < blocksize; n++) 
            {
                fr[n] = in[inoff + n];
            }
            
            cipher.processblock(fr, 0, fre, 0);

            count += blocksize;

            return 0;
        }
        else if (count == blocksize)
        {
            // copy in buffer so that this mode works if in and out are the same 
            system.arraycopy(in, inoff, tmp, 0, blocksize);
        
            system.arraycopy(fr, 2, fr, 0, blocksize - 2);
            
            fr[blocksize - 2] = tmp[0];
            fr[blocksize - 1] = tmp[1];

            cipher.processblock(fr, 0, fre, 0);

            for (int n = 0; n < blocksize - 2; n++) 
            {
                out[outoff + n] = encryptbyte(tmp[n + 2], n);
            }

            system.arraycopy(tmp, 2, fr, 0, blocksize - 2);

            count += 2;

            return blocksize - 2;
        }
        else if (count >= blocksize + 2)
        {
            // copy in buffer so that this mode works if in and out are the same 
            system.arraycopy(in, inoff, tmp, 0, blocksize);

            out[outoff + 0] = encryptbyte(tmp[0], blocksize - 2);
            out[outoff + 1] = encryptbyte(tmp[1], blocksize - 1);

            system.arraycopy(tmp, 0, fr, blocksize - 2, 2);

            cipher.processblock(fr, 0, fre, 0);
            
            for (int n = 0; n < blocksize - 2; n++) 
            {
                out[outoff + n + 2] = encryptbyte(tmp[n + 2], n);
            }
            
            system.arraycopy(tmp, 2, fr, 0, blocksize - 2);
            
        } 
        
        return blocksize;
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
        
        cipher.processblock(fr, 0, fre, 0);
        for (int n = 0; n < blocksize; n++) 
        {
            out[outoff + n] = encryptbyte(in[inoff + n], n);
        }
        
        for (int n = 0; n < blocksize; n++) 
        {
            fr[n] = out[outoff + n];
        }
        
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
        
        cipher.processblock(fr, 0, fre, 0);
        for (int n = 0; n < blocksize; n++) 
        {
            out[outoff + n] = encryptbyte(in[inoff + n], n);
        }
        
        for (int n = 0; n < blocksize; n++) 
        {
            fr[n] = in[inoff + n];
        }
        
        return blocksize;
        
    }
}
