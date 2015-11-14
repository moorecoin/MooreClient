package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.paddings.blockcipherpadding;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * implements a cipher-feedback (cfb) mode on top of a simple cipher.
 */
class maccfbblockcipher
{
    private byte[]          iv;
    private byte[]          cfbv;
    private byte[]          cfboutv;

    private int                 blocksize;
    private blockcipher         cipher = null;

    /**
     * basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the
     * feedback mode.
     * @param blocksize the block size in bits (note: a multiple of 8)
     */
    public maccfbblockcipher(
        blockcipher         cipher,
        int                 bitblocksize)
    {
        this.cipher = cipher;
        this.blocksize = bitblocksize / 8;

        this.iv = new byte[cipher.getblocksize()];
        this.cfbv = new byte[cipher.getblocksize()];
        this.cfboutv = new byte[cipher.getblocksize()];
    }

    /**
     * initialise the cipher and, possibly, the initialisation vector (iv).
     * if an iv isn't passed as part of the parameter, the iv will be all zeros.
     * an iv which is too short is handled in fips compliant fashion.
     *
     * @param param the key and other data required by the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
        cipherparameters    params)
        throws illegalargumentexception
    {
        if (params instanceof parameterswithiv)
        {
                parameterswithiv ivparam = (parameterswithiv)params;
                byte[]      iv = ivparam.getiv();

                if (iv.length < iv.length)
                {
                    system.arraycopy(iv, 0, iv, iv.length - iv.length, iv.length);
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
        // xor the cfbv with the plaintext producing the cipher text
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
     * reset the chaining vector back to the iv and reset the underlying
     * cipher.
     */
    public void reset()
    {
        system.arraycopy(iv, 0, cfbv, 0, iv.length);

        cipher.reset();
    }

    void getmacblock(
        byte[]  mac)
    {
        cipher.processblock(cfbv, 0, mac, 0);
    }
}

public class cfbblockciphermac
    implements mac
{
    private byte[]              mac;

    private byte[]              buf;
    private int                 bufoff;
    private maccfbblockcipher   cipher;
    private blockcipherpadding  padding = null;


    private int                 macsize;

    /**
     * create a standard mac based on a cfb block cipher. this will produce an
     * authentication code half the length of the block size of the cipher, with
     * the cfb mode set to 8 bits.
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     */
    public cfbblockciphermac(
        blockcipher     cipher)
    {
        this(cipher, 8, (cipher.getblocksize() * 8) / 2, null);
    }

    /**
     * create a standard mac based on a cfb block cipher. this will produce an
     * authentication code half the length of the block size of the cipher, with
     * the cfb mode set to 8 bits.
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     * @param padding the padding to be used.
     */
    public cfbblockciphermac(
        blockcipher         cipher,
        blockcipherpadding  padding)
    {
        this(cipher, 8, (cipher.getblocksize() * 8) / 2, padding);
    }

    /**
     * create a standard mac based on a block cipher with the size of the
     * mac been given in bits. this class uses cfb mode as the basis for the
     * mac generation.
     * <p>
     * note: the size of the mac must be at least 24 bits (fips publication 81),
     * or 16 bits if being used as a data authenticator (fips publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see handbook of applied cryptography).
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     * @param cfbbitsize the size of an output block produced by the cfb mode.
     * @param macsizeinbits the size of the mac in bits, must be a multiple of 8.
     */
    public cfbblockciphermac(
        blockcipher         cipher,
        int                 cfbbitsize,
        int                 macsizeinbits)
    {
        this(cipher, cfbbitsize, macsizeinbits, null);
    }

    /**
     * create a standard mac based on a block cipher with the size of the
     * mac been given in bits. this class uses cfb mode as the basis for the
     * mac generation.
     * <p>
     * note: the size of the mac must be at least 24 bits (fips publication 81),
     * or 16 bits if being used as a data authenticator (fips publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see handbook of applied cryptography).
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     * @param cfbbitsize the size of an output block produced by the cfb mode.
     * @param macsizeinbits the size of the mac in bits, must be a multiple of 8.
     * @param padding a padding to be used.
     */
    public cfbblockciphermac(
        blockcipher         cipher,
        int                 cfbbitsize,
        int                 macsizeinbits,
        blockcipherpadding  padding)
    {
        if ((macsizeinbits % 8) != 0)
        {
            throw new illegalargumentexception("mac size must be multiple of 8");
        }

        mac = new byte[cipher.getblocksize()];

        this.cipher = new maccfbblockcipher(cipher, cfbbitsize);
        this.padding = padding;
        this.macsize = macsizeinbits / 8;

        buf = new byte[this.cipher.getblocksize()];
        bufoff = 0;
    }

    public string getalgorithmname()
    {
        return cipher.getalgorithmname();
    }

    public void init(
        cipherparameters    params)
    {
        reset();

        cipher.init(params);
    }

    public int getmacsize()
    {
        return macsize;
    }

    public void update(
        byte        in)
    {
        if (bufoff == buf.length)
        {
            cipher.processblock(buf, 0, mac, 0);
            bufoff = 0;
        }

        buf[bufoff++] = in;
    }

    public void update(
        byte[]      in,
        int         inoff,
        int         len)
    {
        if (len < 0)
        {
            throw new illegalargumentexception("can't have a negative input length!");
        }

        int blocksize = cipher.getblocksize();
        int resultlen = 0;
        int gaplen = blocksize - bufoff;

        if (len > gaplen)
        {
            system.arraycopy(in, inoff, buf, bufoff, gaplen);

            resultlen += cipher.processblock(buf, 0, mac, 0);

            bufoff = 0;
            len -= gaplen;
            inoff += gaplen;

            while (len > blocksize)
            {
                resultlen += cipher.processblock(in, inoff, mac, 0);

                len -= blocksize;
                inoff += blocksize;
            }
        }

        system.arraycopy(in, inoff, buf, bufoff, len);

        bufoff += len;
    }

    public int dofinal(
        byte[]  out,
        int     outoff)
    {
        int blocksize = cipher.getblocksize();

        //
        // pad with zeroes
        //
        if (this.padding == null)
        {
            while (bufoff < blocksize)
            {
                buf[bufoff] = 0;
                bufoff++;
            }
        }
        else
        {
            padding.addpadding(buf, bufoff);
        }

        cipher.processblock(buf, 0, mac, 0);

        cipher.getmacblock(mac);

        system.arraycopy(mac, 0, out, outoff, macsize);

        reset();

        return macsize;
    }

    /**
     * reset the mac generator.
     */
    public void reset()
    {
        /*
         * clean the buffer.
         */
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] = 0;
        }

        bufoff = 0;

        /*
         * reset the underlying cipher.
         */
        cipher.reset();
    }
}
