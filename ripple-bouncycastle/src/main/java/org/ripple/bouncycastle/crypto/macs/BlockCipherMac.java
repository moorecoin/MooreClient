package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;

public class blockciphermac
    implements mac
{
    private byte[]          mac;

    private byte[]          buf;
    private int             bufoff;
    private blockcipher     cipher;

    private int             macsize;

    /**
     * create a standard mac based on a block cipher. this will produce an
     * authentication code half the length of the block size of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     * @deprecated use cbcblockciphermac
     */
    public blockciphermac(
        blockcipher     cipher)
    {
        this(cipher, (cipher.getblocksize() * 8) / 2);
    }

    /**
     * create a standard mac based on a block cipher with the size of the
     * mac been given in bits.
     * <p>
     * note: the size of the mac must be at least 16 bits (fips publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see handbook of applied cryptography).
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     * @param macsizeinbits the size of the mac in bits, must be a multiple of 8.
     * @deprecated use cbcblockciphermac
     */
    public blockciphermac(
        blockcipher     cipher,
        int             macsizeinbits)
    {
        if ((macsizeinbits % 8) != 0)
        {
            throw new illegalargumentexception("mac size must be multiple of 8");
        }

        this.cipher = new cbcblockcipher(cipher);
        this.macsize = macsizeinbits / 8;

        mac = new byte[cipher.getblocksize()];

        buf = new byte[cipher.getblocksize()];
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

        cipher.init(true, params);
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
        while (bufoff < blocksize)
        {
            buf[bufoff] = 0;
            bufoff++;
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
