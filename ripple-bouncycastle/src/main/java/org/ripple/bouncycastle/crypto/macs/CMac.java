package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.paddings.iso7816d4padding;

/**
 * cmac - as specified at www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
 * <p>
 * cmac is analogous to omac1 - see also en.wikipedia.org/wiki/cmac
 * </p><p>
 * cmac is a nist recomendation - see 
 * csrc.nist.gov/cryptotoolkit/modes/800-38_series_publications/sp800-38b.pdf
 * </p><p>
 * cmac/omac1 is a blockcipher-based message authentication code designed and
 * analyzed by tetsu iwata and kaoru kurosawa.
 * </p><p>
 * cmac/omac1 is a simple variant of the cbc mac (cipher block chaining message 
 * authentication code). omac stands for one-key cbc mac.
 * </p><p>
 * it supports 128- or 64-bits block ciphers, with any key size, and returns
 * a mac with dimension less or equal to the block size of the underlying 
 * cipher.
 * </p>
 */
public class cmac implements mac
{
    private static final byte constant_128 = (byte)0x87;
    private static final byte constant_64 = (byte)0x1b;

    private byte[] zeroes;

    private byte[] mac;

    private byte[] buf;
    private int bufoff;
    private blockcipher cipher;

    private int macsize;

    private byte[] l, lu, lu2;

    /**
     * create a standard mac based on a cbc block cipher (64 or 128 bit block).
     * this will produce an authentication code the length of the block size
     * of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     */
    public cmac(blockcipher cipher)
    {
        this(cipher, cipher.getblocksize() * 8);
    }

    /**
     * create a standard mac based on a block cipher with the size of the
     * mac been given in bits.
     * <p/>
     * note: the size of the mac must be at least 24 bits (fips publication 81),
     * or 16 bits if being used as a data authenticator (fips publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see handbook of applied cryptography).
     *
     * @param cipher        the cipher to be used as the basis of the mac generation.
     * @param macsizeinbits the size of the mac in bits, must be a multiple of 8 and <= 128.
     */
    public cmac(blockcipher cipher, int macsizeinbits)
    {
        if ((macsizeinbits % 8) != 0)
        {
            throw new illegalargumentexception("mac size must be multiple of 8");
        }

        if (macsizeinbits > (cipher.getblocksize() * 8))
        {
            throw new illegalargumentexception(
                "mac size must be less or equal to "
                    + (cipher.getblocksize() * 8));
        }

        if (cipher.getblocksize() != 8 && cipher.getblocksize() != 16)
        {
            throw new illegalargumentexception(
                "block size must be either 64 or 128 bits");
        }

        this.cipher = new cbcblockcipher(cipher);
        this.macsize = macsizeinbits / 8;

        mac = new byte[cipher.getblocksize()];

        buf = new byte[cipher.getblocksize()];

        zeroes = new byte[cipher.getblocksize()];

        bufoff = 0;
    }

    public string getalgorithmname()
    {
        return cipher.getalgorithmname();
    }

    private static byte[] doublelu(byte[] in)
    {
        int firstbit = (in[0] & 0xff) >> 7;
        byte[] ret = new byte[in.length];
        for (int i = 0; i < in.length - 1; i++)
        {
            ret[i] = (byte)((in[i] << 1) + ((in[i + 1] & 0xff) >> 7));
        }
        ret[in.length - 1] = (byte)(in[in.length - 1] << 1);
        if (firstbit == 1)
        {
            ret[in.length - 1] ^= in.length == 16 ? constant_128 : constant_64;
        }
        return ret;
    }

    public void init(cipherparameters params)
    {
        if (params != null)
        {
            cipher.init(true, params);
    
            //initializes the l, lu, lu2 numbers
            l = new byte[zeroes.length];
            cipher.processblock(zeroes, 0, l, 0);
            lu = doublelu(l);
            lu2 = doublelu(lu);
        }

        reset();
    }

    public int getmacsize()
    {
        return macsize;
    }

    public void update(byte in)
    {
        if (bufoff == buf.length)
        {
            cipher.processblock(buf, 0, mac, 0);
            bufoff = 0;
        }

        buf[bufoff++] = in;
    }

    public void update(byte[] in, int inoff, int len)
    {
        if (len < 0)
        {
            throw new illegalargumentexception(
                "can't have a negative input length!");
        }

        int blocksize = cipher.getblocksize();
        int gaplen = blocksize - bufoff;

        if (len > gaplen)
        {
            system.arraycopy(in, inoff, buf, bufoff, gaplen);

            cipher.processblock(buf, 0, mac, 0);

            bufoff = 0;
            len -= gaplen;
            inoff += gaplen;

            while (len > blocksize)
            {
                cipher.processblock(in, inoff, mac, 0);

                len -= blocksize;
                inoff += blocksize;
            }
        }

        system.arraycopy(in, inoff, buf, bufoff, len);

        bufoff += len;
    }

    public int dofinal(byte[] out, int outoff)
    {
        int blocksize = cipher.getblocksize();

        byte[] lu;
        if (bufoff == blocksize)
        {
            lu = lu;
        }
        else
        {
            new iso7816d4padding().addpadding(buf, bufoff);
            lu = lu2;
        }

        for (int i = 0; i < mac.length; i++)
        {
            buf[i] ^= lu[i];
        }

        cipher.processblock(buf, 0, mac, 0);

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
