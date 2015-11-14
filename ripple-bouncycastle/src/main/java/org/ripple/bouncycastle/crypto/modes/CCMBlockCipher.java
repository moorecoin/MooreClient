package org.ripple.bouncycastle.crypto.modes;

import java.io.bytearrayoutputstream;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.macs.cbcblockciphermac;
import org.ripple.bouncycastle.crypto.params.aeadparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.util.arrays;

/**
 * implements the counter with cipher block chaining mode (ccm) detailed in
 * nist special publication 800-38c.
 * <p>
 * <b>note</b>: this mode is a packet mode - it needs all the data up front.
 */
public class ccmblockcipher
    implements aeadblockcipher
{
    private blockcipher           cipher;
    private int                   blocksize;
    private boolean               forencryption;
    private byte[]                nonce;
    private byte[]                initialassociatedtext;
    private int                   macsize;
    private cipherparameters      keyparam;
    private byte[]                macblock;
    private bytearrayoutputstream associatedtext = new bytearrayoutputstream();
    private bytearrayoutputstream data = new bytearrayoutputstream();

    /**
     * basic constructor.
     *
     * @param c the block cipher to be used.
     */
    public ccmblockcipher(blockcipher c)
    {
        this.cipher = c;
        this.blocksize = c.getblocksize();
        this.macblock = new byte[blocksize];
        
        if (blocksize != 16)
        {
            throw new illegalargumentexception("cipher required with a block size of 16.");
        }
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


    public void init(boolean forencryption, cipherparameters params)
          throws illegalargumentexception
    {
        this.forencryption = forencryption;

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
            macsize = macblock.length / 2;
            keyparam = param.getparameters();
        }
        else
        {
            throw new illegalargumentexception("invalid parameters passed to ccm");
        }

        if (nonce == null || nonce.length < 7 || nonce.length > 13)
        {
            throw new illegalargumentexception("nonce must have length from 7 to 13 octets");
        }
    }

    public string getalgorithmname()
    {
        return cipher.getalgorithmname() + "/ccm";
    }

    public void processaadbyte(byte in)
    {
        associatedtext.write(in);
    }

    public void processaadbytes(byte[] in, int inoff, int len)
    {
        // todo: process aad online
        associatedtext.write(in, inoff, len);
    }

    public int processbyte(byte in, byte[] out, int outoff)
        throws datalengthexception, illegalstateexception
    {
        data.write(in);

        return 0;
    }

    public int processbytes(byte[] in, int inoff, int inlen, byte[] out, int outoff)
        throws datalengthexception, illegalstateexception
    {
        data.write(in, inoff, inlen);

        return 0;
    }

    public int dofinal(byte[] out, int outoff)
        throws illegalstateexception, invalidciphertextexception
    {
        byte[] text = data.tobytearray();
        byte[] enc = processpacket(text, 0, text.length);

        system.arraycopy(enc, 0, out, outoff, enc.length);

        reset();

        return enc.length;
    }

    public void reset()
    {
        cipher.reset();
        associatedtext.reset();
        data.reset();
    }

    /**
     * returns a byte array containing the mac calculated as part of the
     * last encrypt or decrypt operation.
     * 
     * @return the last mac calculated.
     */
    public byte[] getmac()
    {
        byte[] mac = new byte[macsize];
        
        system.arraycopy(macblock, 0, mac, 0, mac.length);
        
        return mac;
    }

    public int getupdateoutputsize(int len)
    {
        return 0;
    }

    public int getoutputsize(int len)
    {
        int totaldata = len + data.size();

        if (forencryption)
        {
             return totaldata + macsize;
        }

        return totaldata < macsize ? 0 : totaldata - macsize;
    }

    public byte[] processpacket(byte[] in, int inoff, int inlen)
        throws illegalstateexception, invalidciphertextexception
    {
        // todo: handle null keyparam (e.g. via repeatedkeyspec)
        // need to keep the ctr and cbc mac parts around and reset
        if (keyparam == null)
        {
            throw new illegalstateexception("ccm cipher unitialized.");
        }

        int n = nonce.length;
        int q = 15 - n;
        if (q < 4)
        {
            int limitlen = 1 << (8 * q);
            if (inlen >= limitlen)
            {
                throw new illegalstateexception("ccm packet too large for choice of q.");
            }
        }

        byte[] iv = new byte[blocksize];
        iv[0] = (byte)((q - 1) & 0x7);
        system.arraycopy(nonce, 0, iv, 1, nonce.length);

        blockcipher ctrcipher = new sicblockcipher(cipher);
        ctrcipher.init(forencryption, new parameterswithiv(keyparam, iv));

        int index = inoff;
        int outoff = 0;
        byte[] output;

        if (forencryption)
        {
            output = new byte[inlen + macsize];

            calculatemac(in, inoff, inlen, macblock);

            ctrcipher.processblock(macblock, 0, macblock, 0);   // s0

            while (index < inlen - blocksize)                   // s1...
            {
                ctrcipher.processblock(in, index, output, outoff);
                outoff += blocksize;
                index += blocksize;
            }

            byte[] block = new byte[blocksize];

            system.arraycopy(in, index, block, 0, inlen - index);

            ctrcipher.processblock(block, 0, block, 0);

            system.arraycopy(block, 0, output, outoff, inlen - index);

            outoff += inlen - index;

            system.arraycopy(macblock, 0, output, outoff, output.length - outoff);
        }
        else
        {
            output = new byte[inlen - macsize];

            system.arraycopy(in, inoff + inlen - macsize, macblock, 0, macsize);

            ctrcipher.processblock(macblock, 0, macblock, 0);

            for (int i = macsize; i != macblock.length; i++)
            {
                macblock[i] = 0;
            }

            while (outoff < output.length - blocksize)
            {
                ctrcipher.processblock(in, index, output, outoff);
                outoff += blocksize;
                index += blocksize;
            }

            byte[] block = new byte[blocksize];

            system.arraycopy(in, index, block, 0, output.length - outoff);

            ctrcipher.processblock(block, 0, block, 0);

            system.arraycopy(block, 0, output, outoff, output.length - outoff);

            byte[] calculatedmacblock = new byte[blocksize];

            calculatemac(output, 0, output.length, calculatedmacblock);

            if (!arrays.constanttimeareequal(macblock, calculatedmacblock))
            {
                throw new invalidciphertextexception("mac check in ccm failed");
            }
        }

        return output;
    }

    private int calculatemac(byte[] data, int dataoff, int datalen, byte[] macblock)
    {
        mac cmac = new cbcblockciphermac(cipher, macsize * 8);

        cmac.init(keyparam);

        //
        // build b0
        //
        byte[] b0 = new byte[16];
    
        if (hasassociatedtext())
        {
            b0[0] |= 0x40;
        }
        
        b0[0] |= (((cmac.getmacsize() - 2) / 2) & 0x7) << 3;

        b0[0] |= ((15 - nonce.length) - 1) & 0x7;
        
        system.arraycopy(nonce, 0, b0, 1, nonce.length);
        
        int q = datalen;
        int count = 1;
        while (q > 0)
        {
            b0[b0.length - count] = (byte)(q & 0xff);
            q >>>= 8;
            count++;
        }
        
        cmac.update(b0, 0, b0.length);
        
        //
        // process associated text
        //
        if (hasassociatedtext())
        {
            int extra;
            
            int textlength = getassociatedtextlength();
            if (textlength < ((1 << 16) - (1 << 8)))
            {
                cmac.update((byte)(textlength >> 8));
                cmac.update((byte)textlength);
                
                extra = 2;
            }
            else // can't go any higher than 2^32
            {
                cmac.update((byte)0xff);
                cmac.update((byte)0xfe);
                cmac.update((byte)(textlength >> 24));
                cmac.update((byte)(textlength >> 16));
                cmac.update((byte)(textlength >> 8));
                cmac.update((byte)textlength);
                
                extra = 6;
            }

            if (initialassociatedtext != null)
            {
                cmac.update(initialassociatedtext, 0, initialassociatedtext.length);
            }
            if (associatedtext.size() > 0)
            {
                byte[] tmp = associatedtext.tobytearray();
                cmac.update(tmp, 0, tmp.length);
            }

            extra = (extra + textlength) % 16;
            if (extra != 0)
            {
                for (int i = extra; i != 16; i++)
                {
                    cmac.update((byte)0x00);
                }
            }
        }
 
        //
        // add the text
        //
        cmac.update(data, dataoff, datalen);

        return cmac.dofinal(macblock, 0);
    }

    private int getassociatedtextlength()
    {
        return associatedtext.size() + ((initialassociatedtext == null) ? 0 : initialassociatedtext.length);
    }

    private boolean hasassociatedtext()
    {
        return getassociatedtextlength() > 0;
    }
}
