package org.ripple.bouncycastle.crypto.encodings;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;

/**
 * optimal asymmetric encryption padding (oaep) - see pkcs 1 v 2.
 */
public class oaepencoding
    implements asymmetricblockcipher
{
    private byte[]                  defhash;
    private digest                  mgf1hash;

    private asymmetricblockcipher   engine;
    private securerandom            random;
    private boolean                 forencryption;

    public oaepencoding(
        asymmetricblockcipher   cipher)
    {
        this(cipher, new sha1digest(), null);
    }
    
    public oaepencoding(
        asymmetricblockcipher       cipher,
        digest                      hash)
    {
        this(cipher, hash, null);
    }
    
    public oaepencoding(
        asymmetricblockcipher       cipher,
        digest                      hash,
        byte[]                      encodingparams)
    {
        this(cipher, hash, hash, encodingparams);
    }

    public oaepencoding(
        asymmetricblockcipher       cipher,
        digest                      hash,
        digest                      mgf1hash,
        byte[]                      encodingparams)
    {
        this.engine = cipher;
        this.mgf1hash = mgf1hash;
        this.defhash = new byte[hash.getdigestsize()];

        hash.reset();

        if (encodingparams != null)
        {
            hash.update(encodingparams, 0, encodingparams.length);
        }

        hash.dofinal(defhash, 0);
    }

    public asymmetricblockcipher getunderlyingcipher()
    {
        return engine;
    }

    public void init(
        boolean             forencryption,
        cipherparameters    param)
    {
        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom  rparam = (parameterswithrandom)param;

            this.random = rparam.getrandom();
        }
        else
        {   
            this.random = new securerandom();
        }

        engine.init(forencryption, param);

        this.forencryption = forencryption;
    }

    public int getinputblocksize()
    {
        int     baseblocksize = engine.getinputblocksize();

        if (forencryption)
        {
            return baseblocksize - 1 - 2 * defhash.length;
        }
        else
        {
            return baseblocksize;
        }
    }

    public int getoutputblocksize()
    {
        int     baseblocksize = engine.getoutputblocksize();

        if (forencryption)
        {
            return baseblocksize;
        }
        else
        {
            return baseblocksize - 1 - 2 * defhash.length;
        }
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

    public byte[] encodeblock(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        byte[]  block = new byte[getinputblocksize() + 1 + 2 * defhash.length];

        //
        // copy in the message
        //
        system.arraycopy(in, inoff, block, block.length - inlen, inlen);

        //
        // add sentinel
        //
        block[block.length - inlen - 1] = 0x01;

        //
        // as the block is already zeroed - there's no need to add ps (the >= 0 pad of 0)
        //

        //
        // add the hash of the encoding params.
        //
        system.arraycopy(defhash, 0, block, defhash.length, defhash.length);

        //
        // generate the seed.
        //
        byte[]  seed = new byte[defhash.length];

        random.nextbytes(seed);

        //
        // mask the message block.
        //
        byte[]  mask = maskgeneratorfunction1(seed, 0, seed.length, block.length - defhash.length);

        for (int i = defhash.length; i != block.length; i++)
        {
            block[i] ^= mask[i - defhash.length];
        }

        //
        // add in the seed
        //
        system.arraycopy(seed, 0, block, 0, defhash.length);

        //
        // mask the seed.
        //
        mask = maskgeneratorfunction1(
                        block, defhash.length, block.length - defhash.length, defhash.length);

        for (int i = 0; i != defhash.length; i++)
        {
            block[i] ^= mask[i];
        }

        return engine.processblock(block, 0, block.length);
    }

    /**
     * @exception invalidciphertextexception if the decrypted block turns out to
     * be badly formatted.
     */
    public byte[] decodeblock(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        byte[]  data = engine.processblock(in, inoff, inlen);
        byte[]  block;

        //
        // as we may have zeros in our leading bytes for the block we produced
        // on encryption, we need to make sure our decrypted block comes back
        // the same size.
        //
        if (data.length < engine.getoutputblocksize())
        {
            block = new byte[engine.getoutputblocksize()];

            system.arraycopy(data, 0, block, block.length - data.length, data.length);
        }
        else
        {
            block = data;
        }

        if (block.length < (2 * defhash.length) + 1)
        {
            throw new invalidciphertextexception("data too short");
        }

        //
        // unmask the seed.
        //
        byte[] mask = maskgeneratorfunction1(
                    block, defhash.length, block.length - defhash.length, defhash.length);

        for (int i = 0; i != defhash.length; i++)
        {
            block[i] ^= mask[i];
        }

        //
        // unmask the message block.
        //
        mask = maskgeneratorfunction1(block, 0, defhash.length, block.length - defhash.length);

        for (int i = defhash.length; i != block.length; i++)
        {
            block[i] ^= mask[i - defhash.length];
        }

        //
        // check the hash of the encoding params.
        // long check to try to avoid this been a source of a timing attack.
        //
        boolean defhashwrong = false;

        for (int i = 0; i != defhash.length; i++)
        {
            if (defhash[i] != block[defhash.length + i])
            {
                defhashwrong = true;
            }
        }

        if (defhashwrong)
        {
            throw new invalidciphertextexception("data hash wrong");
        }

        //
        // find the data block
        //
        int start;

        for (start = 2 * defhash.length; start != block.length; start++)
        {
            if (block[start] != 0)
            {
                break;
            }
        }

        if (start >= (block.length - 1) || block[start] != 1)
        {
            throw new invalidciphertextexception("data start wrong " + start);
        }

        start++;

        //
        // extract the data block
        //
        byte[]  output = new byte[block.length - start];

        system.arraycopy(block, start, output, 0, output.length);

        return output;
    }

    /**
     * int to octet string.
     */
    private void itoosp(
        int     i,
        byte[]  sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }

    /**
     * mask generator function, as described in pkcs1v2.
     */
    private byte[] maskgeneratorfunction1(
        byte[]  z,
        int     zoff,
        int     zlen,
        int     length)
    {
        byte[]  mask = new byte[length];
        byte[]  hashbuf = new byte[mgf1hash.getdigestsize()];
        byte[]  c = new byte[4];
        int     counter = 0;

        mgf1hash.reset();

        while (counter < (length / hashbuf.length))
        {
            itoosp(counter, c);

            mgf1hash.update(z, zoff, zlen);
            mgf1hash.update(c, 0, c.length);
            mgf1hash.dofinal(hashbuf, 0);

            system.arraycopy(hashbuf, 0, mask, counter * hashbuf.length, hashbuf.length);

            counter++;
        }

        if ((counter * hashbuf.length) < length)
        {
            itoosp(counter, c);

            mgf1hash.update(z, zoff, zlen);
            mgf1hash.update(c, 0, c.length);
            mgf1hash.dofinal(hashbuf, 0);

            system.arraycopy(hashbuf, 0, mask, counter * hashbuf.length, mask.length - (counter * hashbuf.length));
        }

        return mask;
    }
}
