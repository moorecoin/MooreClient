package org.ripple.bouncycastle.crypto.encodings;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;

/**
 * iso 9796-1 padding. note in the light of recent results you should
 * only use this with rsa (rather than the "simpler" rabin keys) and you
 * should never use it with anything other than a hash (ie. even if the
 * message is small don't sign the message, sign it's hash) or some "random"
 * value. see your favorite search engine for details.
 */
public class iso9796d1encoding
    implements asymmetricblockcipher
{
    private static final biginteger sixteen = biginteger.valueof(16l);
    private static final biginteger six     = biginteger.valueof(6l);

    private static byte[]    shadows = { 0xe, 0x3, 0x5, 0x8, 0x9, 0x4, 0x2, 0xf,
                                    0x0, 0xd, 0xb, 0x6, 0x7, 0xa, 0xc, 0x1 };
    private static byte[]    inverse = { 0x8, 0xf, 0x6, 0x1, 0x5, 0x2, 0xb, 0xc,
                                    0x3, 0x4, 0xd, 0xa, 0xe, 0x9, 0x0, 0x7 };

    private asymmetricblockcipher   engine;
    private boolean                 forencryption;
    private int                     bitsize;
    private int                     padbits = 0;
    private biginteger              modulus;

    public iso9796d1encoding(
        asymmetricblockcipher   cipher)
    {
        this.engine = cipher;
    }

    public asymmetricblockcipher getunderlyingcipher()
    {
        return engine;
    }

    public void init(
        boolean             forencryption,
        cipherparameters    param)
    {
        rsakeyparameters  kparam = null;

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom    rparam = (parameterswithrandom)param;

            kparam = (rsakeyparameters)rparam.getparameters();
        }
        else
        {
            kparam = (rsakeyparameters)param;
        }

        engine.init(forencryption, param);

        modulus = kparam.getmodulus();
        bitsize = modulus.bitlength();

        this.forencryption = forencryption;
    }

    /**
     * return the input block size. the largest message we can process
     * is (key_size_in_bits + 3)/16, which in our world comes to
     * key_size_in_bytes / 2.
     */
    public int getinputblocksize()
    {
        int     baseblocksize = engine.getinputblocksize();

        if (forencryption)
        {
            return (baseblocksize + 1) / 2;
        }
        else
        {
            return baseblocksize;
        }
    }

    /**
     * return the maximum possible size for the output.
     */
    public int getoutputblocksize()
    {
        int     baseblocksize = engine.getoutputblocksize();

        if (forencryption)
        {
            return baseblocksize;
        }
        else
        {
            return (baseblocksize + 1) / 2;
        }
    }

    /**
     * set the number of bits in the next message to be treated as
     * pad bits.
     */
    public void setpadbits(
        int     padbits)
    {
        if (padbits > 7)
        {
            throw new illegalargumentexception("padbits > 7");
        }

        this.padbits = padbits;
    }

    /**
     * retrieve the number of pad bits in the last decoded message.
     */
    public int getpadbits()
    {
        return padbits;
    }

    public byte[] processblock(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        if (forencryption)
        {
            return encodeblock(in, inoff, inlen);
        }
        else
        {
            return decodeblock(in, inoff, inlen);
        }
    }

    private byte[] encodeblock(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        byte[]  block = new byte[(bitsize + 7) / 8];
        int     r = padbits + 1;
        int     z = inlen;
        int     t = (bitsize + 13) / 16;

        for (int i = 0; i < t; i += z)
        {
            if (i > t - z)
            {
                system.arraycopy(in, inoff + inlen - (t - i),
                                    block, block.length - t, t - i);
            }
            else
            {
                system.arraycopy(in, inoff, block, block.length - (i + z), z);
            }
        }

        for (int i = block.length - 2 * t; i != block.length; i += 2)
        {
            byte    val = block[block.length - t + i / 2];

            block[i] = (byte)((shadows[(val & 0xff) >>> 4] << 4)
                                                | shadows[val & 0x0f]);
            block[i + 1] = val;
        }

        block[block.length - 2 * z] ^= r;
        block[block.length - 1] = (byte)((block[block.length - 1] << 4) | 0x06);

        int maxbit = (8 - (bitsize - 1) % 8);
        int offset = 0;

        if (maxbit != 8)
        {
            block[0] &= 0xff >>> maxbit;
            block[0] |= 0x80 >>> maxbit;
        }
        else
        {
            block[0] = 0x00;
            block[1] |= 0x80;
            offset = 1;
        }

        return engine.processblock(block, offset, block.length - offset);
    }

    /**
     * @exception invalidciphertextexception if the decrypted block is not a valid iso 9796 bit string
     */
    private byte[] decodeblock(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        byte[]  block = engine.processblock(in, inoff, inlen);
        int     r = 1;
        int     t = (bitsize + 13) / 16;

        biginteger is = new biginteger(1, block);
        biginteger ir;
        if (is.mod(sixteen).equals(six))
        {
            ir = is;
        }
        else if ((modulus.subtract(is)).mod(sixteen).equals(six))
        {
            ir = modulus.subtract(is);
        }
        else
        {
            throw new invalidciphertextexception("resulting integer is or (modulus - is) is not congruent to 6 mod 16");
        }

        block = convertoutputdecryptonly(ir);

        if ((block[block.length - 1] & 0x0f) != 0x6 )
        {
            throw new invalidciphertextexception("invalid forcing byte in block");
        }

        block[block.length - 1] = (byte)(((block[block.length - 1] & 0xff) >>> 4) | ((inverse[(block[block.length - 2] & 0xff) >> 4]) << 4));
        block[0] = (byte)((shadows[(block[1] & 0xff) >>> 4] << 4)
                                                | shadows[block[1] & 0x0f]);

        boolean boundaryfound = false;
        int     boundary = 0;

        for (int i = block.length - 1; i >= block.length - 2 * t; i -= 2)
        {
            int val = ((shadows[(block[i] & 0xff) >>> 4] << 4)
                                        | shadows[block[i] & 0x0f]);

            if (((block[i - 1] ^ val) & 0xff) != 0)
            {
                if (!boundaryfound)
                {
                    boundaryfound = true;
                    r = (block[i - 1] ^ val) & 0xff;
                    boundary = i - 1;
                }
                else
                {
                    throw new invalidciphertextexception("invalid tsums in block");
                }
            }
        }

        block[boundary] = 0;

        byte[]  nblock = new byte[(block.length - boundary) / 2];

        for (int i = 0; i < nblock.length; i++)
        {
            nblock[i] = block[2 * i + boundary + 1];
        }

        padbits = r - 1;

        return nblock;
    }

    private static byte[] convertoutputdecryptonly(biginteger result)
    {
        byte[] output = result.tobytearray();
        if (output[0] == 0) // have ended up with an extra zero byte, copy down.
        {
            byte[] tmp = new byte[output.length - 1];
            system.arraycopy(output, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return output;
    }
}
