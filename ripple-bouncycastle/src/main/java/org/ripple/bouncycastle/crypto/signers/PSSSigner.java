package org.ripple.bouncycastle.crypto.signers;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsablindingparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;

/**
 * rsa-pss as described in pkcs# 1 v 2.1.
 * <p>
 * note: the usual value for the salt length is the number of
 * bytes in the hash function.
 */
public class psssigner
    implements signer
{
    static final public byte   trailer_implicit    = (byte)0xbc;

    private digest                      contentdigest;
    private digest                      mgfdigest;
    private asymmetricblockcipher       cipher;
    private securerandom                random;

    private int                         hlen;
    private int                         mgfhlen;
    private int                         slen;
    private int                         embits;
    private byte[]                      salt;
    private byte[]                      mdash;
    private byte[]                      block;
    private byte                        trailer;

    /**
     * basic constructor
     *
     * @param cipher the asymmetric cipher to use.
     * @param digest the digest to use.
     * @param slen the length of the salt to use (in bytes).
     */
    public psssigner(
        asymmetricblockcipher   cipher,
        digest                  digest,
        int                     slen)
    {
        this(cipher, digest, slen, trailer_implicit);
    }

    public psssigner(
        asymmetricblockcipher   cipher,
        digest                  contentdigest,
        digest                  mgfdigest,
        int                     slen)
    {
        this(cipher, contentdigest, mgfdigest, slen, trailer_implicit);
    }

    public psssigner(
            asymmetricblockcipher   cipher,
            digest                  digest,
            int                     slen,
            byte                    trailer)
    {
        this(cipher, digest, digest, slen, trailer);
    }

    public psssigner(
        asymmetricblockcipher   cipher,
        digest                  contentdigest,
        digest                  mgfdigest,
        int                     slen,
        byte                    trailer)
    {
        this.cipher = cipher;
        this.contentdigest = contentdigest;
        this.mgfdigest = mgfdigest;
        this.hlen = contentdigest.getdigestsize();
        this.mgfhlen = mgfdigest.getdigestsize();
        this.slen = slen;
        this.salt = new byte[slen];
        this.mdash = new byte[8 + slen + hlen];
        this.trailer = trailer;
    }

    public void init(
        boolean                 forsigning,
        cipherparameters        param)
    {
        cipherparameters  params;

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom    p = (parameterswithrandom)param;

            params = p.getparameters();
            random = p.getrandom();
        }
        else
        {
            params = param;
            if (forsigning)
            {
                random = new securerandom();
            }
        }

        cipher.init(forsigning, params);

        rsakeyparameters kparam;

        if (params instanceof rsablindingparameters)
        {
            kparam = ((rsablindingparameters)params).getpublickey();
        }
        else
        {
            kparam = (rsakeyparameters)params;
        }
        
        embits = kparam.getmodulus().bitlength() - 1;

        if (embits < (8 * hlen + 8 * slen + 9))
        {
            throw new illegalargumentexception("key too small for specified hash and salt lengths");
        }

        block = new byte[(embits + 7) / 8];

        reset();
    }

    /**
     * clear possible sensitive data
     */
    private void clearblock(
        byte[]  block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte    b)
    {
        contentdigest.update(b);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  in,
        int     off,
        int     len)
    {
        contentdigest.update(in, off, len);
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        contentdigest.reset();
    }

    /**
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generatesignature()
        throws cryptoexception, datalengthexception
    {
        contentdigest.dofinal(mdash, mdash.length - hlen - slen);

        if (slen != 0)
        {
            random.nextbytes(salt);

            system.arraycopy(salt, 0, mdash, mdash.length - slen, slen);
        }

        byte[]  h = new byte[hlen];

        contentdigest.update(mdash, 0, mdash.length);

        contentdigest.dofinal(h, 0);

        block[block.length - slen - 1 - hlen - 1] = 0x01;
        system.arraycopy(salt, 0, block, block.length - slen - hlen - 1, slen);

        byte[] dbmask = maskgeneratorfunction1(h, 0, h.length, block.length - hlen - 1);
        for (int i = 0; i != dbmask.length; i++)
        {
            block[i] ^= dbmask[i];
        }

        block[0] &= (0xff >> ((block.length * 8) - embits));

        system.arraycopy(h, 0, block, block.length - hlen - 1, hlen);

        block[block.length - 1] = trailer;

        byte[]  b = cipher.processblock(block, 0, block.length);

        clearblock(block);

        return b;
    }

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     */
    public boolean verifysignature(
        byte[]      signature)
    {
        contentdigest.dofinal(mdash, mdash.length - hlen - slen);

        try
        {
            byte[] b = cipher.processblock(signature, 0, signature.length);
            system.arraycopy(b, 0, block, block.length - b.length, b.length);
        }
        catch (exception e)
        {
            return false;
        }

        if (block[block.length - 1] != trailer)
        {
            clearblock(block);
            return false;
        }

        byte[] dbmask = maskgeneratorfunction1(block, block.length - hlen - 1, hlen, block.length - hlen - 1);

        for (int i = 0; i != dbmask.length; i++)
        {
            block[i] ^= dbmask[i];
        }

        block[0] &= (0xff >> ((block.length * 8) - embits));

        for (int i = 0; i != block.length - hlen - slen - 2; i++)
        {
            if (block[i] != 0)
            {
                clearblock(block);
                return false;
            }
        }

        if (block[block.length - hlen - slen - 2] != 0x01)
        {
            clearblock(block);
            return false;
        }

        system.arraycopy(block, block.length - slen - hlen - 1, mdash, mdash.length - slen, slen);

        contentdigest.update(mdash, 0, mdash.length);
        contentdigest.dofinal(mdash, mdash.length - hlen);

        for (int i = block.length - hlen - 1, j = mdash.length - hlen;
                                                 j != mdash.length; i++, j++)
        {
            if ((block[i] ^ mdash[j]) != 0)
            {
                clearblock(mdash);
                clearblock(block);
                return false;
            }
        }

        clearblock(mdash);
        clearblock(block);

        return true;
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
        byte[]  hashbuf = new byte[mgfhlen];
        byte[]  c = new byte[4];
        int     counter = 0;

        mgfdigest.reset();

        while (counter < (length / mgfhlen))
        {
            itoosp(counter, c);

            mgfdigest.update(z, zoff, zlen);
            mgfdigest.update(c, 0, c.length);
            mgfdigest.dofinal(hashbuf, 0);

            system.arraycopy(hashbuf, 0, mask, counter * mgfhlen, mgfhlen);

            counter++;
        }

        if ((counter * mgfhlen) < length)
        {
            itoosp(counter, c);

            mgfdigest.update(z, zoff, zlen);
            mgfdigest.update(c, 0, c.length);
            mgfdigest.dofinal(hashbuf, 0);

            system.arraycopy(hashbuf, 0, mask, counter * mgfhlen, mask.length - (counter * mgfhlen));
        }

        return mask;
    }
}
