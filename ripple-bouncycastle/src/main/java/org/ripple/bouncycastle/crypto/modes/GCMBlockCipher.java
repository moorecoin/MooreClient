package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.modes.gcm.gcmexponentiator;
import org.ripple.bouncycastle.crypto.modes.gcm.gcmmultiplier;
import org.ripple.bouncycastle.crypto.modes.gcm.tables1kgcmexponentiator;
import org.ripple.bouncycastle.crypto.modes.gcm.tables8kgcmmultiplier;
import org.ripple.bouncycastle.crypto.params.aeadparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.arrays;

/**
 * implements the galois/counter mode (gcm) detailed in
 * nist special publication 800-38d.
 */
public class gcmblockcipher
    implements aeadblockcipher
{
    private static final int block_size = 16;

    // not final due to a compiler bug 
    private blockcipher   cipher;
    private gcmmultiplier multiplier;
    private gcmexponentiator exp;

    // these fields are set by init and not modified by processing
    private boolean             forencryption;
    private int                 macsize;
    private byte[]              nonce;
    private byte[]              initialassociatedtext;
    private byte[]              h;
    private byte[]              j0;

    // these fields are modified during processing
    private byte[]      bufblock;
    private byte[]      macblock;
    private byte[]      s, s_at, s_atpre;
    private byte[]      counter;
    private int         bufoff;
    private long        totallength;
    private byte[]      atblock;
    private int         atblockpos;
    private long        atlength;
    private long        atlengthpre;

    public gcmblockcipher(blockcipher c)
    {
        this(c, null);
    }

    public gcmblockcipher(blockcipher c, gcmmultiplier m)
    {
        if (c.getblocksize() != block_size)
        {
            throw new illegalargumentexception(
                "cipher required with a block size of " + block_size + ".");
        }

        if (m == null)
        {
            // todo consider a static property specifying default multiplier
            m = new tables8kgcmmultiplier();
        }

        this.cipher = c;
        this.multiplier = m;
    }

    public blockcipher getunderlyingcipher()
    {
        return cipher;
    }

    public string getalgorithmname()
    {
        return cipher.getalgorithmname() + "/gcm";
    }

    public void init(boolean forencryption, cipherparameters params)
        throws illegalargumentexception
    {
        this.forencryption = forencryption;
        this.macblock = null;

        keyparameter keyparam;

        if (params instanceof aeadparameters)
        {
            aeadparameters param = (aeadparameters)params;

            nonce = param.getnonce();
            initialassociatedtext = param.getassociatedtext();

            int macsizebits = param.getmacsize();
            if (macsizebits < 96 || macsizebits > 128 || macsizebits % 8 != 0)
            {
                throw new illegalargumentexception("invalid value for mac size: " + macsizebits);
            }

            macsize = macsizebits / 8; 
            keyparam = param.getkey();
        }
        else if (params instanceof parameterswithiv)
        {
            parameterswithiv param = (parameterswithiv)params;

            nonce = param.getiv();
            initialassociatedtext  = null;
            macsize = 16;
            keyparam = (keyparameter)param.getparameters();
        }
        else
        {
            throw new illegalargumentexception("invalid parameters passed to gcm");
        }

        int buflength = forencryption ? block_size : (block_size + macsize); 
        this.bufblock = new byte[buflength];

        if (nonce == null || nonce.length < 1)
        {
            throw new illegalargumentexception("iv must be at least 1 byte");
        }

        // todo this should be configurable by init parameters
        // (but must be 16 if nonce length not 12) (block_size?)
//        this.taglength = 16;

        // cipher always used in forward mode
        // if keyparam is null we're reusing the last key.
        if (keyparam != null)
        {
            cipher.init(true, keyparam);

            this.h = new byte[block_size];
            cipher.processblock(h, 0, h, 0);

            // gcmmultiplier tables don't change unless the key changes (and are expensive to init)
            multiplier.init(h);
            exp = null;
        }

        this.j0 = new byte[block_size];

        if (nonce.length == 12)
        {
            system.arraycopy(nonce, 0, j0, 0, nonce.length);
            this.j0[block_size - 1] = 0x01;
        }
        else
        {
            ghash(j0, nonce, nonce.length);
            byte[] x = new byte[block_size];
            pack.longtobigendian((long)nonce.length * 8, x, 8);
            ghashblock(j0, x);
        }

        this.s = new byte[block_size];
        this.s_at = new byte[block_size];
        this.s_atpre = new byte[block_size];
        this.atblock = new byte[block_size];
        this.atblockpos = 0;
        this.atlength = 0;
        this.atlengthpre = 0;
        this.counter = arrays.clone(j0);
        this.bufoff = 0;
        this.totallength = 0;

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
        int totaldata = len + bufoff;

        if (forencryption)
        {
             return totaldata + macsize;
        }

        return totaldata < macsize ? 0 : totaldata - macsize;
    }

    public int getupdateoutputsize(int len)
    {
        int totaldata = len + bufoff;
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

    public void processaadbyte(byte in)
    {
        atblock[atblockpos] = in;
        if (++atblockpos == block_size)
        {
            // hash each block as it fills
            ghashblock(s_at, atblock);
            atblockpos = 0;
            atlength += block_size;
        }
    }

    public void processaadbytes(byte[] in, int inoff, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            atblock[atblockpos] = in[inoff + i];
            if (++atblockpos == block_size)
            {
                // hash each block as it fills
                ghashblock(s_at, atblock);
                atblockpos = 0;
                atlength += block_size;
            }
        }
    }

    private void initcipher()
    {
        if (atlength > 0)
        {
            system.arraycopy(s_at, 0, s_atpre, 0, block_size);
            atlengthpre = atlength;
        }

        // finish hash for partial aad block
        if (atblockpos > 0)
        {
            ghashpartial(s_atpre, atblock, 0, atblockpos);
            atlengthpre += atblockpos;
        }

        if (atlengthpre > 0)
        {
            system.arraycopy(s_atpre, 0, s, 0, block_size);
        }
    }

    public int processbyte(byte in, byte[] out, int outoff)
        throws datalengthexception
    {
        bufblock[bufoff] = in;
        if (++bufoff == bufblock.length)
        {
            outputblock(out, outoff);
            return block_size;
        }
        return 0;
    }

    public int processbytes(byte[] in, int inoff, int len, byte[] out, int outoff)
        throws datalengthexception
    {
        int resultlen = 0;

        for (int i = 0; i < len; ++i)
        {
            bufblock[bufoff] = in[inoff + i];
            if (++bufoff == bufblock.length)
            {
                outputblock(out, outoff + resultlen);
                resultlen += block_size;
            }
        }

        return resultlen;
    }

    private void outputblock(byte[] output, int offset)
    {
        if (totallength == 0)
        {
            initcipher();
        }
        gctrblock(bufblock, output, offset);
        if (forencryption)
        {
            bufoff = 0;
        }
        else
        {
            system.arraycopy(bufblock, block_size, bufblock, 0, macsize);
            bufoff = macsize;
        }
    }

    public int dofinal(byte[] out, int outoff)
        throws illegalstateexception, invalidciphertextexception
    {
        if (totallength == 0)
        {
            initcipher();
        }

        int extra = bufoff;
        if (!forencryption)
        {
            if (extra < macsize)
            {
                throw new invalidciphertextexception("data too short");
            }
            extra -= macsize;
        }

        if (extra > 0)
        {
            gctrpartial(bufblock, 0, extra, out, outoff);
        }

        atlength += atblockpos;

        if (atlength > atlengthpre)
        {
            /*
             *  some aad was sent after the cipher started. we determine the difference b/w the hash value
             *  we actually used when the cipher started (s_atpre) and the final hash value calculated (s_at).
             *  then we carry this difference forward by multiplying by h^c, where c is the number of (full or
             *  partial) cipher-text blocks produced, and adjust the current hash.
             */

            // finish hash for partial aad block
            if (atblockpos > 0)
            {
                ghashpartial(s_at, atblock, 0, atblockpos);
            }

            // find the difference between the aad hashes
            if (atlengthpre > 0)
            {
                xor(s_at, s_atpre);
            }

            // number of cipher-text blocks produced
            long c = ((totallength * 8) + 127) >>> 7;

            // calculate the adjustment factor
            byte[] h_c = new byte[16];
            if (exp == null)
            {
                exp = new tables1kgcmexponentiator();
                exp.init(h);
            }
            exp.exponentiatex(c, h_c);

            // carry the difference forward
            multiply(s_at, h_c);

            // adjust the current hash
            xor(s, s_at);
        }

        // final ghash
        byte[] x = new byte[block_size];
        pack.longtobigendian(atlength * 8, x, 0);
        pack.longtobigendian(totallength * 8, x, 8);

        ghashblock(s, x);

        // todo fix this if taglength becomes configurable
        // t = msbt(gctrk(j0,s))
        byte[] tag = new byte[block_size];
        cipher.processblock(j0, 0, tag, 0);
        xor(tag, s);

        int resultlen = extra;

        // we place into macblock our calculated value for t
        this.macblock = new byte[macsize];
        system.arraycopy(tag, 0, macblock, 0, macsize);

        if (forencryption)
        {
            // append t to the message
            system.arraycopy(macblock, 0, out, outoff + bufoff, macsize);
            resultlen += macsize;
        }
        else
        {
            // retrieve the t value from the message and compare to calculated one
            byte[] msgmac = new byte[macsize];
            system.arraycopy(bufblock, extra, msgmac, 0, macsize);
            if (!arrays.constanttimeareequal(this.macblock, msgmac))
            {
                throw new invalidciphertextexception("mac check in gcm failed");
            }
        }

        reset(false);

        return resultlen;
    }

    public void reset()
    {
        reset(true);
    }

    private void reset(
        boolean clearmac)
    {
        cipher.reset();

        s = new byte[block_size];
        s_at = new byte[block_size];
        s_atpre = new byte[block_size];
        atblock = new byte[block_size];
        atblockpos = 0;
        atlength = 0;
        atlengthpre = 0;
        counter = arrays.clone(j0);
        bufoff = 0;
        totallength = 0;

        if (bufblock != null)
        {
            arrays.fill(bufblock, (byte)0);
        }

        if (clearmac)
        {
            macblock = null;
        }

        if (initialassociatedtext != null)
        {
            processaadbytes(initialassociatedtext, 0, initialassociatedtext.length);
        }
    }

    private void gctrblock(byte[] block, byte[] out, int outoff)
    {
        byte[] tmp = getnextcounterblock();

        xor(tmp, block);
        system.arraycopy(tmp, 0, out, outoff, block_size);

        ghashblock(s, forencryption ? tmp : block);

        totallength += block_size;
    }

    private void gctrpartial(byte[] buf, int off, int len, byte[] out, int outoff)
    {
        byte[] tmp = getnextcounterblock();

        xor(tmp, buf, off, len);
        system.arraycopy(tmp, 0, out, outoff, len);

        ghashpartial(s, forencryption ? tmp : buf, 0, len);

        totallength += len;
    }

    private void ghash(byte[] y, byte[] b, int len)
    {
        for (int pos = 0; pos < len; pos += block_size)
        {
            int num = math.min(len - pos, block_size);
            ghashpartial(y, b, pos, num);
        }
    }

    private void ghashblock(byte[] y, byte[] b)
    {
        xor(y, b);
        multiplier.multiplyh(y);
    }

    private void ghashpartial(byte[] y, byte[] b, int off, int len)
    {
        xor(y, b, off, len);
        multiplier.multiplyh(y);
    }

    private byte[] getnextcounterblock()
    {
        for (int i = 15; i >= 12; --i)
        {
            byte b = (byte)((counter[i] + 1) & 0xff);
            counter[i] = b;

            if (b != 0)
            {
                break;
            }
        }

        byte[] tmp = new byte[block_size];
        // todo sure would be nice if ciphers could operate on int[]
        cipher.processblock(counter, 0, tmp, 0);
        return tmp;
    }

    private static void multiply(byte[] block, byte[] val)
    {
        byte[] tmp = arrays.clone(block);
        byte[] c = new byte[16];

        for (int i = 0; i < 16; ++i)
        {
            byte bits = val[i];
            for (int j = 7; j >= 0; --j)
            {
                if ((bits & (1 << j)) != 0)
                {
                    xor(c, tmp);
                }

                boolean lsb = (tmp[15] & 1) != 0;
                shiftright(tmp);
                if (lsb)
                {
                    // r = new byte[]{ 0xe1, ... };
//                    xor(v, r);
                    tmp[0] ^= (byte)0xe1;
                }
            }
        }

        system.arraycopy(c, 0, block, 0, 16);
    }

    private static void shiftright(byte[] block)
    {
        int i = 0;
        int bit = 0;
        for (;;)
        {
            int b = block[i] & 0xff;
            block[i] = (byte) ((b >>> 1) | bit);
            if (++i == 16)
            {
                break;
            }
            bit = (b & 1) << 7;
        }
    }

    private static void xor(byte[] block, byte[] val)
    {
        for (int i = 15; i >= 0; --i)
        {
            block[i] ^= val[i];
        }
    }

    private static void xor(byte[] block, byte[] val, int off, int len)
    {
        while (len-- > 0)
        {
            block[len] ^= val[off + len];
        }
    }
}
