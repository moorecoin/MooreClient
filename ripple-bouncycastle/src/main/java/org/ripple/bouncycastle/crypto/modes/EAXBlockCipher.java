package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.macs.cmac;
import org.ripple.bouncycastle.crypto.params.aeadparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.util.arrays;

/**
 * a two-pass authenticated-encryption scheme optimized for simplicity and 
 * efficiency - by m. bellare, p. rogaway, d. wagner.
 * 
 * http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
 * 
 * eax is an aead scheme based on ctr and omac1/cmac, that uses a single block 
 * cipher to encrypt and authenticate data. it's on-line (the length of a 
 * message isn't needed to begin processing it), has good performances, it's
 * simple and provably secure (provided the underlying block cipher is secure).
 * 
 * of course, this implementations is not thread-safe.
 */
public class eaxblockcipher
    implements aeadblockcipher
{
    private static final byte ntag = 0x0;

    private static final byte htag = 0x1;

    private static final byte ctag = 0x2;

    private sicblockcipher cipher;

    private boolean forencryption;

    private int blocksize;

    private mac mac;

    private byte[] noncemac;
    private byte[] associatedtextmac;
    private byte[] macblock;
    
    private int macsize;
    private byte[] bufblock;
    private int bufoff;

    private boolean cipherinitialized;
    private byte[] initialassociatedtext;

    /**
     * constructor that accepts an instance of a block cipher engine.
     *
     * @param cipher the engine to use
     */
    public eaxblockcipher(blockcipher cipher)
    {
        blocksize = cipher.getblocksize();
        mac = new cmac(cipher);
        macblock = new byte[blocksize];
        bufblock = new byte[blocksize * 2];
        associatedtextmac = new byte[mac.getmacsize()];
        noncemac = new byte[mac.getmacsize()];
        this.cipher = new sicblockcipher(cipher);
    }

    public string getalgorithmname()
    {
        return cipher.getunderlyingcipher().getalgorithmname() + "/eax";
    }

    public blockcipher getunderlyingcipher()
    {
        return cipher.getunderlyingcipher();
    }

    public int getblocksize()
    {
        return cipher.getblocksize();
    }

    public void init(boolean forencryption, cipherparameters params)
        throws illegalargumentexception
    {
        this.forencryption = forencryption;

        byte[] nonce;
        cipherparameters keyparam;

        if (params instanceof aeadparameters)
        {
            aeadparameters param = (aeadparameters)params;

            nonce = param.getnonce();
            initialassociatedtext = param.getassociatedtext();
            macsize = param.getmacsize() / 8;
            keyparam = param.getkey();
        }
        else if (params instanceof parameterswithiv)
        {
            parameterswithiv param = (parameterswithiv)params;

            nonce = param.getiv();
            initialassociatedtext = null;
            macsize = mac.getmacsize() / 2;
            keyparam = param.getparameters();
        }
        else
        {
            throw new illegalargumentexception("invalid parameters passed to eax");
        }

        byte[] tag = new byte[blocksize];

        // key reuse implemented in cbc mode of underlying cmac
        mac.init(keyparam);

        tag[blocksize - 1] = ntag;
        mac.update(tag, 0, blocksize);
        mac.update(nonce, 0, nonce.length);
        mac.dofinal(noncemac, 0);

        tag[blocksize - 1] = htag;
        mac.update(tag, 0, blocksize);

        if (initialassociatedtext != null)
        {
            processaadbytes(initialassociatedtext, 0, initialassociatedtext.length);
        }

        // same blockcipher underlies this and the mac, so reuse last key on cipher 
        cipher.init(true, new parameterswithiv(null, noncemac));
    }

    private void initcipher()
    {
        if (cipherinitialized)
        {
            return;
        }

        cipherinitialized = true;

        mac.dofinal(associatedtextmac, 0);

        byte[] tag = new byte[blocksize];
        tag[blocksize - 1] = ctag;
        mac.update(tag, 0, blocksize);
    }

    private void calculatemac()
    {
        byte[] outc = new byte[blocksize];
        mac.dofinal(outc, 0);

        for (int i = 0; i < macblock.length; i++)
        {
            macblock[i] = (byte)(noncemac[i] ^ associatedtextmac[i] ^ outc[i]);
        }
    }

    public void reset()
    {
        reset(true);
    }

    private void reset(
        boolean clearmac)
    {
        cipher.reset(); // todo redundant since the mac will reset it?
        mac.reset();

        bufoff = 0;
        arrays.fill(bufblock, (byte)0);

        if (clearmac)
        {
            arrays.fill(macblock, (byte)0);
        }

        byte[] tag = new byte[blocksize];
        tag[blocksize - 1] = htag;
        mac.update(tag, 0, blocksize);

        cipherinitialized = false;

        if (initialassociatedtext != null)
        {
           processaadbytes(initialassociatedtext, 0, initialassociatedtext.length);
        }
    }

    public void processaadbyte(byte in)
    {
        if (cipherinitialized)
        {
            throw new illegalstateexception("aad data cannot be added after encryption/decription processing has begun.");
        }
        mac.update(in);
    }

    public void processaadbytes(byte[] in, int inoff, int len)
    {
        if (cipherinitialized)
        {
            throw new illegalstateexception("aad data cannot be added after encryption/decription processing has begun.");
        }
        mac.update(in, inoff, len);
    }

    public int processbyte(byte in, byte[] out, int outoff)
        throws datalengthexception
    {
        initcipher();

        return process(in, out, outoff);
    }

    public int processbytes(byte[] in, int inoff, int len, byte[] out, int outoff)
        throws datalengthexception
    {
        initcipher();

        int resultlen = 0;

        for (int i = 0; i != len; i++)
        {
            resultlen += process(in[inoff + i], out, outoff + resultlen);
        }

        return resultlen;
    }

    public int dofinal(byte[] out, int outoff)
        throws illegalstateexception, invalidciphertextexception
    {
        initcipher();

        int extra = bufoff;
        byte[] tmp = new byte[bufblock.length];

        bufoff = 0;

        if (forencryption)
        {
            cipher.processblock(bufblock, 0, tmp, 0);
            cipher.processblock(bufblock, blocksize, tmp, blocksize);

            system.arraycopy(tmp, 0, out, outoff, extra);

            mac.update(tmp, 0, extra);

            calculatemac();

            system.arraycopy(macblock, 0, out, outoff + extra, macsize);

            reset(false);

            return extra + macsize;
        }
        else
        {
            if (extra > macsize)
            {
                mac.update(bufblock, 0, extra - macsize);

                cipher.processblock(bufblock, 0, tmp, 0);
                cipher.processblock(bufblock, blocksize, tmp, blocksize);

                system.arraycopy(tmp, 0, out, outoff, extra - macsize);
            }

            calculatemac();

            if (!verifymac(bufblock, extra - macsize))
            {
                throw new invalidciphertextexception("mac check in eax failed");
            }

            reset(false);

            return extra - macsize;
        }
    }

    public byte[] getmac()
    {
        byte[] mac = new byte[macsize];

        system.arraycopy(macblock, 0, mac, 0, macsize);

        return mac;
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
        return totaldata - totaldata % blocksize;
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

    private int process(byte b, byte[] out, int outoff)
    {
        bufblock[bufoff++] = b;

        if (bufoff == bufblock.length)
        {
            // todo could move the processbyte(s) calls to here
//            initcipher();

            int size;

            if (forencryption)
            {
                size = cipher.processblock(bufblock, 0, out, outoff);

                mac.update(out, outoff, blocksize);
            }
            else
            {
                mac.update(bufblock, 0, blocksize);

                size = cipher.processblock(bufblock, 0, out, outoff);
            }

            bufoff = blocksize;
            system.arraycopy(bufblock, blocksize, bufblock, 0, blocksize);

            return size;
        }

        return 0;
    }

    private boolean verifymac(byte[] mac, int off)
    {
        int nonequal = 0;

        for (int i = 0; i < macsize; i++)
        {
            nonequal |= (macblock[i] ^ mac[off + i]);
        }

        return nonequal == 0;
    }
}
