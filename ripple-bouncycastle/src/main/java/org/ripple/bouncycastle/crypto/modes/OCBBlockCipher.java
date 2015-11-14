package org.ripple.bouncycastle.crypto.modes;

import java.util.vector;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.params.aeadparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.util.arrays;

/**
 * an implementation of the "work in progress" internet-draft <a
 * href="http://tools.ietf.org/html/draft-irtf-cfrg-ocb-00">the ocb authenticated-encryption
 * algorithm</a>, licensed per:
 * <p/>
 * <blockquote> <a href="http://www.cs.ucdavis.edu/~rogaway/ocb/license1.pdf">license for
 * open-source software implementations of ocb</a> (jan 9, 2013) &mdash; &ldquo;license 1&rdquo; <br>
 * under this license, you are authorized to make, use, and distribute open-source software
 * implementations of ocb. this license terminates for you if you sue someone over their open-source
 * software implementation of ocb claiming that you have a patent covering their implementation.
 * <p/>
 * this is a non-binding summary of a legal document (the link above). the parameters of the license
 * are specified in the license document and that document is controlling. </blockquote>
 */
public class ocbblockcipher
    implements aeadblockcipher
{

    private static final int block_size = 16;

    private blockcipher hashcipher;
    private blockcipher maincipher;

    /*
     * configuration
     */
    private boolean forencryption;
    private int macsize;
    private byte[] initialassociatedtext;

    /*
     * key-dependent
     */
    // note: elements are lazily calculated
    private vector l;
    private byte[] l_asterisk, l_dollar;

    /*
     * nonce-dependent
     */
    private byte[] offsetmain_0;

    /*
     * per-encryption/decryption
     */
    private byte[] hashblock, mainblock;
    private int hashblockpos, mainblockpos;
    private long hashblockcount, mainblockcount;
    private byte[] offsethash;
    private byte[] sum;
    private byte[] offsetmain;
    private byte[] checksum;

    // note: the mac value is preserved after dofinal
    private byte[] macblock;

    public ocbblockcipher(blockcipher hashcipher, blockcipher maincipher)
    {
        if (hashcipher == null)
        {
            throw new illegalargumentexception("'hashcipher' cannot be null");
        }
        if (hashcipher.getblocksize() != block_size)
        {
            throw new illegalargumentexception("'hashcipher' must have a block size of "
                + block_size);
        }
        if (maincipher == null)
        {
            throw new illegalargumentexception("'maincipher' cannot be null");
        }
        if (maincipher.getblocksize() != block_size)
        {
            throw new illegalargumentexception("'maincipher' must have a block size of "
                + block_size);
        }

        if (!hashcipher.getalgorithmname().equals(maincipher.getalgorithmname()))
        {
            throw new illegalargumentexception(
                "'hashcipher' and 'maincipher' must be the same algorithm");
        }

        this.hashcipher = hashcipher;
        this.maincipher = maincipher;
    }

    public blockcipher getunderlyingcipher()
    {
        return maincipher;
    }

    public string getalgorithmname()
    {
        return maincipher.getalgorithmname() + "/ocb";
    }

    public void init(boolean forencryption, cipherparameters parameters)
        throws illegalargumentexception
    {

        this.forencryption = forencryption;
        this.macblock = null;

        keyparameter keyparameter;

        byte[] n;
        if (parameters instanceof aeadparameters)
        {
            aeadparameters aeadparameters = (aeadparameters)parameters;

            n = aeadparameters.getnonce();
            initialassociatedtext = aeadparameters.getassociatedtext();

            int macsizebits = aeadparameters.getmacsize();
            if (macsizebits < 64 || macsizebits > 128 || macsizebits % 8 != 0)
            {
                throw new illegalargumentexception("invalid value for mac size: " + macsizebits);
            }

            macsize = macsizebits / 8;
            keyparameter = aeadparameters.getkey();
        }
        else if (parameters instanceof parameterswithiv)
        {
            parameterswithiv parameterswithiv = (parameterswithiv)parameters;

            n = parameterswithiv.getiv();
            initialassociatedtext = null;
            macsize = 16;
            keyparameter = (keyparameter)parameterswithiv.getparameters();
        }
        else
        {
            throw new illegalargumentexception("invalid parameters passed to ocb");
        }

        this.hashblock = new byte[16];
        this.mainblock = new byte[forencryption ? block_size : (block_size + macsize)];

        if (n == null)
        {
            n = new byte[0];
        }

        if (n.length > 16 || (n.length == 16 && (n[0] & 0x80) != 0))
        {
            /*
             * note: we don't just ignore bit 128 because it would hide from the caller the fact
             * that two nonces differing only in bit 128 are not different.
             */
            throw new illegalargumentexception("iv must be no more than 127 bits");
        }

        /*
         * key-dependent initialisation
         */

        // if keyparam is null we're reusing the last key.
        if (keyparameter != null)
        {
            // todo
        }

        // hashcipher always used in forward mode
        hashcipher.init(true, keyparameter);
        maincipher.init(forencryption, keyparameter);

        this.l_asterisk = new byte[16];
        hashcipher.processblock(l_asterisk, 0, l_asterisk, 0);

        this.l_dollar = ocb_double(l_asterisk);

        this.l = new vector();
        this.l.addelement(ocb_double(l_dollar));

        /*
         * nonce-dependent and per-encryption/decryption initialisation
         */

        byte[] nonce = new byte[16];
        system.arraycopy(n, 0, nonce, nonce.length - n.length, n.length);
        if (n.length == 16)
        {
            nonce[0] &= 0x80;
        }
        else
        {
            nonce[15 - n.length] = 1;
        }

        int bottom = nonce[15] & 0x3f;
        // system.out.println("bottom: " + bottom);

        byte[] ktop = new byte[16];
        nonce[15] &= 0xc0;
        hashcipher.processblock(nonce, 0, ktop, 0);

        byte[] stretch = new byte[24];
        system.arraycopy(ktop, 0, stretch, 0, 16);
        for (int i = 0; i < 8; ++i)
        {
            stretch[16 + i] = (byte)(ktop[i] ^ ktop[i + 1]);
        }

        this.offsetmain_0 = new byte[16];
        int bits = bottom % 8, bytes = bottom / 8;
        if (bits == 0)
        {
            system.arraycopy(stretch, bytes, offsetmain_0, 0, 16);
        }
        else
        {
            for (int i = 0; i < 16; ++i)
            {
                int b1 = stretch[bytes] & 0xff;
                int b2 = stretch[++bytes] & 0xff;
                this.offsetmain_0[i] = (byte)((b1 << bits) | (b2 >>> (8 - bits)));
            }
        }

        this.hashblockpos = 0;
        this.mainblockpos = 0;

        this.hashblockcount = 0;
        this.mainblockcount = 0;

        this.offsethash = new byte[16];
        this.sum = new byte[16];
        this.offsetmain = arrays.clone(this.offsetmain_0);
        this.checksum = new byte[16];

        if (initialassociatedtext != null)
        {
            processaadbytes(initialassociatedtext, 0, initialassociatedtext.length);
        }
    }

    public byte[] getmac()
    {
        return arrays.clone(macblock);
    }

    public int getoutputsize(int len)
    {
        int totaldata = len + mainblockpos;
        if (forencryption)
        {
            return totaldata + macsize;
        }
        return totaldata < macsize ? 0 : totaldata - macsize;
    }

    public int getupdateoutputsize(int len)
    {
        int totaldata = len + mainblockpos;
        if (!forencryption)
        {
            if (totaldata < macsize)
            {
                return 0;
            }
            totaldata -= macsize;
        }
        return totaldata - totaldata % block_size;
    }

    public void processaadbyte(byte input)
    {
        hashblock[hashblockpos] = input;
        if (++hashblockpos == hashblock.length)
        {
            processhashblock();
        }
    }

    public void processaadbytes(byte[] input, int off, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            hashblock[hashblockpos] = input[off + i];
            if (++hashblockpos == hashblock.length)
            {
                processhashblock();
            }
        }
    }

    public int processbyte(byte input, byte[] output, int outoff)
        throws datalengthexception
    {
        mainblock[mainblockpos] = input;
        if (++mainblockpos == mainblock.length)
        {
            processmainblock(output, outoff);
            return block_size;
        }
        return 0;
    }

    public int processbytes(byte[] input, int inoff, int len, byte[] output, int outoff)
        throws datalengthexception
    {

        int resultlen = 0;

        for (int i = 0; i < len; ++i)
        {
            mainblock[mainblockpos] = input[inoff + i];
            if (++mainblockpos == mainblock.length)
            {
                processmainblock(output, outoff + resultlen);
                resultlen += block_size;
            }
        }

        return resultlen;
    }

    public int dofinal(byte[] output, int outoff)
        throws illegalstateexception,
        invalidciphertextexception
    {

        /*
         * for decryption, get the tag from the end of the message
         */
        byte[] tag = null;
        if (!forencryption)
        {
            if (mainblockpos < macsize)
            {
                throw new invalidciphertextexception("data too short");
            }
            mainblockpos -= macsize;
            tag = new byte[macsize];
            system.arraycopy(mainblock, mainblockpos, tag, 0, macsize);
        }

        /*
         * hash: process any final partial block; compute final hash value
         */
        if (hashblockpos > 0)
        {
            ocb_extend(hashblock, hashblockpos);
            updatehash(l_asterisk);
        }

        /*
         * ocb-encrypt/ocb-decrypt: process any final partial block
         */
        if (mainblockpos > 0)
        {
            if (forencryption)
            {
                ocb_extend(mainblock, mainblockpos);
                xor(checksum, mainblock);
            }

            xor(offsetmain, l_asterisk);

            byte[] pad = new byte[16];
            hashcipher.processblock(offsetmain, 0, pad, 0);

            xor(mainblock, pad);

            system.arraycopy(mainblock, 0, output, outoff, mainblockpos);

            if (!forencryption)
            {
                ocb_extend(mainblock, mainblockpos);
                xor(checksum, mainblock);
            }
        }

        /*
         * ocb-encrypt/ocb-decrypt: compute raw tag
         */
        xor(checksum, offsetmain);
        xor(checksum, l_dollar);
        hashcipher.processblock(checksum, 0, checksum, 0);
        xor(checksum, sum);

        this.macblock = new byte[macsize];
        system.arraycopy(checksum, 0, macblock, 0, macsize);

        /*
         * validate or append tag and reset this cipher for the next run
         */
        int resultlen = mainblockpos;

        if (forencryption)
        {
            // append tag to the message
            system.arraycopy(macblock, 0, output, outoff + resultlen, macsize);
            resultlen += macsize;
        }
        else
        {
            // compare the tag from the message with the calculated one
            if (!arrays.constanttimeareequal(macblock, tag))
            {
                throw new invalidciphertextexception("mac check in ocb failed");
            }
        }

        reset(false);

        return resultlen;
    }

    public void reset()
    {
        reset(true);
    }

    protected void clear(byte[] bs)
    {
        if (bs != null)
        {
            arrays.fill(bs, (byte)0);
        }
    }

    protected byte[] getlsub(int n)
    {
        while (n >= l.size())
        {
            l.addelement(ocb_double((byte[])l.lastelement()));
        }
        return (byte[])l.elementat(n);
    }

    protected void processhashblock()
    {
        /*
         * hash: process any whole blocks
         */
        updatehash(getlsub(ocb_ntz(++hashblockcount)));
        hashblockpos = 0;
    }

    protected void processmainblock(byte[] output, int outoff)
    {
        /*
         * ocb-encrypt/ocb-decrypt: process any whole blocks
         */

        if (forencryption)
        {
            xor(checksum, mainblock);
            mainblockpos = 0;
        }

        xor(offsetmain, getlsub(ocb_ntz(++mainblockcount)));

        xor(mainblock, offsetmain);
        maincipher.processblock(mainblock, 0, mainblock, 0);
        xor(mainblock, offsetmain);

        system.arraycopy(mainblock, 0, output, outoff, 16);

        if (!forencryption)
        {
            xor(checksum, mainblock);
            system.arraycopy(mainblock, block_size, mainblock, 0, macsize);
            mainblockpos = macsize;
        }
    }

    protected void reset(boolean clearmac)
    {

        hashcipher.reset();
        maincipher.reset();

        clear(hashblock);
        clear(mainblock);

        hashblockpos = 0;
        mainblockpos = 0;

        hashblockcount = 0;
        mainblockcount = 0;

        clear(offsethash);
        clear(sum);
        system.arraycopy(offsetmain_0, 0, offsetmain, 0, 16);
        clear(checksum);

        if (clearmac)
        {
            macblock = null;
        }

        if (initialassociatedtext != null)
        {
            processaadbytes(initialassociatedtext, 0, initialassociatedtext.length);
        }
    }

    protected void updatehash(byte[] lsub)
    {
        xor(offsethash, lsub);
        xor(hashblock, offsethash);
        hashcipher.processblock(hashblock, 0, hashblock, 0);
        xor(sum, hashblock);
    }

    protected static byte[] ocb_double(byte[] block)
    {
        byte[] result = new byte[16];
        int carry = shiftleft(block, result);

        /*
         * note: this construction is an attempt at a constant-time implementation.
         */
        result[15] ^= (0x87 >>> ((1 - carry) << 3));

        return result;
    }

    protected static void ocb_extend(byte[] block, int pos)
    {
        block[pos] = (byte)0x80;
        while (++pos < 16)
        {
            block[pos] = 0;
        }
    }

    protected static int ocb_ntz(long x)
    {
        if (x == 0)
        {
            return 64;
        }

        int n = 0;
        while ((x & 1l) == 0l)
        {
            ++n;
            x >>= 1;
        }
        return n;
    }

    protected static int shiftleft(byte[] block, byte[] output)
    {
        int i = 16;
        int bit = 0;
        while (--i >= 0)
        {
            int b = block[i] & 0xff;
            output[i] = (byte)((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
        return bit;
    }

    protected static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }
}
