package org.ripple.bouncycastle.crypto.signers;

import java.security.securerandom;
import java.util.hashtable;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.signerwithrecovery;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.parameterswithsalt;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;

/**
 * iso9796-2 - mechanism using a hash function with recovery (scheme 2 and 3).
 * <p/>
 * note: the usual length for the salt is the length of the hash
 * function used in bytes.
 */
public class iso9796d2psssigner
    implements signerwithrecovery
{
    static final public int   trailer_implicit    = 0xbc;
    static final public int   trailer_ripemd160   = 0x31cc;
    static final public int   trailer_ripemd128   = 0x32cc;
    static final public int   trailer_sha1        = 0x33cc;
    static final public int   trailer_sha256      = 0x34cc;
    static final public int   trailer_sha512      = 0x35cc;
    static final public int   trailer_sha384      = 0x36cc;
    static final public int   trailer_whirlpool   = 0x37cc;

    private static hashtable trailermap          = new hashtable();

    static
    {
        trailermap.put("ripemd128", integers.valueof(trailer_ripemd128));
        trailermap.put("ripemd160", integers.valueof(trailer_ripemd160));

        trailermap.put("sha-1", integers.valueof(trailer_sha1));
        trailermap.put("sha-256", integers.valueof(trailer_sha256));
        trailermap.put("sha-384", integers.valueof(trailer_sha384));
        trailermap.put("sha-512", integers.valueof(trailer_sha512));

        trailermap.put("whirlpool", integers.valueof(trailer_whirlpool));
    }

    private digest digest;
    private asymmetricblockcipher cipher;

    private securerandom random;
    private byte[] standardsalt;

    private int hlen;
    private int trailer;
    private int keybits;
    private byte[] block;
    private byte[] mbuf;
    private int messagelength;
    private int saltlength;
    private boolean fullmessage;
    private byte[] recoveredmessage;

    private byte[] presig;
    private byte[] preblock;
    private int premstart;
    private int pretlength;

    /**
     * generate a signer for the with either implicit or explicit trailers
     * for iso9796-2, scheme 2 or 3.
     *
     * @param cipher     base cipher to use for signature creation/verification
     * @param digest     digest to use.
     * @param saltlength length of salt in bytes.
     * @param implicit   whether or not the trailer is implicit or gives the hash.
     */
    public iso9796d2psssigner(
        asymmetricblockcipher cipher,
        digest digest,
        int saltlength,
        boolean implicit)
    {
        this.cipher = cipher;
        this.digest = digest;
        this.hlen = digest.getdigestsize();
        this.saltlength = saltlength;

        if (implicit)
        {
            trailer = trailer_implicit;
        }
        else
        {
            integer trailerobj = (integer)trailermap.get(digest.getalgorithmname());

            if (trailerobj != null)
            {
                trailer = trailerobj.intvalue();
            }
            else
            {
                throw new illegalargumentexception("no valid trailer for digest");
            }
        }
    }

    /**
     * constructor for a signer with an explicit digest trailer.
     *
     * @param cipher     cipher to use.
     * @param digest     digest to sign with.
     * @param saltlength length of salt in bytes.
     */
    public iso9796d2psssigner(
        asymmetricblockcipher cipher,
        digest digest,
        int saltlength)
    {
        this(cipher, digest, saltlength, false);
    }

    /**
     * initialise the signer.
     *
     * @param forsigning true if for signing, false if for verification.
     * @param param      parameters for signature generation/verification. if the
     *                   parameters are for generation they should be a parameterswithrandom,
     *                   a parameterswithsalt, or just an rsakeyparameters object. if rsakeyparameters
     *                   are passed in a securerandom will be created.
     * @throws illegalargumentexception if wrong parameter type or a fixed
     * salt is passed in which is the wrong length.
     */
    public void init(
        boolean forsigning,
        cipherparameters param)
    {
        rsakeyparameters kparam;
        int lengthofsalt = saltlength;

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom p = (parameterswithrandom)param;

            kparam = (rsakeyparameters)p.getparameters();
            if (forsigning)
            {
                random = p.getrandom();
            }
        }
        else if (param instanceof parameterswithsalt)
        {
            parameterswithsalt p = (parameterswithsalt)param;

            kparam = (rsakeyparameters)p.getparameters();
            standardsalt = p.getsalt();
            lengthofsalt = standardsalt.length;
            if (standardsalt.length != saltlength)
            {
                throw new illegalargumentexception("fixed salt is of wrong length");
            }
        }
        else
        {
            kparam = (rsakeyparameters)param;
            if (forsigning)
            {
                random = new securerandom();
            }
        }

        cipher.init(forsigning, kparam);

        keybits = kparam.getmodulus().bitlength();

        block = new byte[(keybits + 7) / 8];

        if (trailer == trailer_implicit)
        {
            mbuf = new byte[block.length - digest.getdigestsize() - lengthofsalt - 1 - 1];
        }
        else
        {
            mbuf = new byte[block.length - digest.getdigestsize() - lengthofsalt - 1 - 2];
        }

        reset();
    }

    /**
     * compare two byte arrays - constant time
     */
    private boolean issameas(
        byte[] a,
        byte[] b)
    {
        boolean isokay = true;

        if (messagelength != b.length)
        {
            isokay = false;
        }

        for (int i = 0; i != b.length; i++)
        {
            if (a[i] != b[i])
            {
                isokay = false;
            }
        }

        return isokay;
    }

    /**
     * clear possible sensitive data
     */
    private void clearblock(
        byte[] block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    public void updatewithrecoveredmessage(byte[] signature)
        throws invalidciphertextexception
    {
        byte[] block = cipher.processblock(signature, 0, signature.length);

        //
        // adjust block size for leading zeroes if necessary
        //
        if (block.length < (keybits + 7) / 8)
        {
            byte[] tmp = new byte[(keybits + 7) / 8];

            system.arraycopy(block, 0, tmp, tmp.length - block.length, block.length);
            clearblock(block);
            block = tmp;
        }

        int tlength;

        if (((block[block.length - 1] & 0xff) ^ 0xbc) == 0)
        {
            tlength = 1;
        }
        else
        {
            int sigtrail = ((block[block.length - 2] & 0xff) << 8) | (block[block.length - 1] & 0xff);

            integer trailerobj = (integer)trailermap.get(digest.getalgorithmname());

            if (trailerobj != null)
            {
                if (sigtrail != trailerobj.intvalue())
                {
                    throw new illegalstateexception("signer initialised with wrong digest for trailer " + sigtrail);
                }
            }
            else
            {
                throw new illegalargumentexception("unrecognised hash in signature");
            }

            tlength = 2;
        }

        //
        // calculate h(m2)
        //
        byte[] m2hash = new byte[hlen];
        digest.dofinal(m2hash, 0);

        //
        // remove the mask
        //
        byte[] dbmask = maskgeneratorfunction1(block, block.length - hlen - tlength, hlen, block.length - hlen - tlength);
        for (int i = 0; i != dbmask.length; i++)
        {
            block[i] ^= dbmask[i];
        }

        block[0] &= 0x7f;

        //
        // find out how much padding we've got
        //
        int mstart = 0;
        for (; mstart != block.length; mstart++)
        {
            if (block[mstart] == 0x01)
            {
                break;
            }
        }

        mstart++;

        if (mstart >= block.length)
        {
            clearblock(block);
        }

        fullmessage = (mstart > 1);

        recoveredmessage = new byte[dbmask.length - mstart - saltlength];

        system.arraycopy(block, mstart, recoveredmessage, 0, recoveredmessage.length);
        system.arraycopy(recoveredmessage, 0, mbuf, 0, recoveredmessage.length);

        presig = signature;
        preblock = block;
        premstart = mstart;
        pretlength = tlength;
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte b)
    {
        if (presig == null && messagelength < mbuf.length)
        {
            mbuf[messagelength++] = b;
        }
        else
        {
            digest.update(b);
        }
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[] in,
        int off,
        int len)
    {
        if (presig == null)
        {
            while (len > 0 && messagelength < mbuf.length)
            {
                this.update(in[off]);
                off++;
                len--;
            }
        }

        if (len > 0)
        {
            digest.update(in, off, len);
        }
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
        messagelength = 0;
        if (mbuf != null)
        {
            clearblock(mbuf);
        }
        if (recoveredmessage != null)
        {
            clearblock(recoveredmessage);
            recoveredmessage = null;
        }
        fullmessage = false;
        if (presig != null)
        {
            presig = null;
            clearblock(preblock);
            preblock = null;
        }
    }

    /**
     * generate a signature for the loaded message using the key we were
     * initialised with.
     */
    public byte[] generatesignature()
        throws cryptoexception
    {
        int digsize = digest.getdigestsize();

        byte[] m2hash = new byte[digsize];

        digest.dofinal(m2hash, 0);

        byte[] c = new byte[8];
        ltoosp(messagelength * 8, c);

        digest.update(c, 0, c.length);

        digest.update(mbuf, 0, messagelength);

        digest.update(m2hash, 0, m2hash.length);

        byte[] salt;

        if (standardsalt != null)
        {
            salt = standardsalt;
        }
        else
        {
            salt = new byte[saltlength];
            random.nextbytes(salt);
        }

        digest.update(salt, 0, salt.length);

        byte[] hash = new byte[digest.getdigestsize()];

        digest.dofinal(hash, 0);

        int tlength = 2;
        if (trailer == trailer_implicit)
        {
            tlength = 1;
        }

        int off = block.length - messagelength - salt.length - hlen - tlength - 1;

        block[off] = 0x01;

        system.arraycopy(mbuf, 0, block, off + 1, messagelength);
        system.arraycopy(salt, 0, block, off + 1 + messagelength, salt.length);

        byte[] dbmask = maskgeneratorfunction1(hash, 0, hash.length, block.length - hlen - tlength);
        for (int i = 0; i != dbmask.length; i++)
        {
            block[i] ^= dbmask[i];
        }

        system.arraycopy(hash, 0, block, block.length - hlen - tlength, hlen);

        if (trailer == trailer_implicit)
        {
            block[block.length - 1] = (byte)trailer_implicit;
        }
        else
        {
            block[block.length - 2] = (byte)(trailer >>> 8);
            block[block.length - 1] = (byte)trailer;
        }

        block[0] &= 0x7f;

        byte[] b = cipher.processblock(block, 0, block.length);

        clearblock(mbuf);
        clearblock(block);
        messagelength = 0;

        return b;
    }

    /**
     * return true if the signature represents a iso9796-2 signature
     * for the passed in message.
     */
    public boolean verifysignature(
        byte[] signature)
    {
        //
        // calculate h(m2)
        //
        byte[] m2hash = new byte[hlen];
        digest.dofinal(m2hash, 0);

        byte[] block;
        int tlength;
        int mstart = 0;

        if (presig == null)
        {
            try
            {
                updatewithrecoveredmessage(signature);
            }
            catch (exception e)
            {
                return false;
            }
        }
        else
        {
            if (!arrays.areequal(presig, signature))
            {
                throw new illegalstateexception("updatewithrecoveredmessage called on different signature");
            }
        }

        block = preblock;
        mstart = premstart;
        tlength = pretlength;

        presig = null;
        preblock = null;

        //
        // check the hashes
        //
        byte[] c = new byte[8];
        ltoosp(recoveredmessage.length * 8, c);

        digest.update(c, 0, c.length);

        if (recoveredmessage.length != 0)
        {
            digest.update(recoveredmessage, 0, recoveredmessage.length);
        }

        digest.update(m2hash, 0, m2hash.length);

        // update for the salt
        digest.update(block, mstart + recoveredmessage.length, saltlength);

        byte[] hash = new byte[digest.getdigestsize()];
        digest.dofinal(hash, 0);

        int off = block.length - tlength - hash.length;

        boolean isokay = true;

        for (int i = 0; i != hash.length; i++)
        {
            if (hash[i] != block[off + i])
            {
                isokay = false;
            }
        }

        clearblock(block);
        clearblock(hash);

        if (!isokay)
        {
            fullmessage = false;
            clearblock(recoveredmessage);
            return false;
        }

        //
        // if they've input a message check what we've recovered against
        // what was input.
        //
        if (messagelength != 0)
        {
            if (!issameas(mbuf, recoveredmessage))
            {
                clearblock(mbuf);
                return false;
            }
            messagelength = 0;
        }

        clearblock(mbuf);
        return true;
    }

    /**
     * return true if the full message was recoveredmessage.
     *
     * @return true on full message recovery, false otherwise, or if not sure.
     * @see org.ripple.bouncycastle.crypto.signerwithrecovery#hasfullmessage()
     */
    public boolean hasfullmessage()
    {
        return fullmessage;
    }

    /**
     * return a reference to the recoveredmessage message.
     *
     * @return the full/partial recoveredmessage message.
     * @see org.ripple.bouncycastle.crypto.signerwithrecovery#getrecoveredmessage()
     */
    public byte[] getrecoveredmessage()
    {
        return recoveredmessage;
    }

    /**
     * int to octet string.
     */
    private void itoosp(
        int i,
        byte[] sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }

    /**
     * long to octet string.
     */
    private void ltoosp(
        long l,
        byte[] sp)
    {
        sp[0] = (byte)(l >>> 56);
        sp[1] = (byte)(l >>> 48);
        sp[2] = (byte)(l >>> 40);
        sp[3] = (byte)(l >>> 32);
        sp[4] = (byte)(l >>> 24);
        sp[5] = (byte)(l >>> 16);
        sp[6] = (byte)(l >>> 8);
        sp[7] = (byte)(l >>> 0);
    }

    /**
     * mask generator function, as described in pkcs1v2.
     */
    private byte[] maskgeneratorfunction1(
        byte[] z,
        int zoff,
        int zlen,
        int length)
    {
        byte[] mask = new byte[length];
        byte[] hashbuf = new byte[hlen];
        byte[] c = new byte[4];
        int counter = 0;

        digest.reset();

        while (counter < (length / hlen))
        {
            itoosp(counter, c);

            digest.update(z, zoff, zlen);
            digest.update(c, 0, c.length);
            digest.dofinal(hashbuf, 0);

            system.arraycopy(hashbuf, 0, mask, counter * hlen, hlen);

            counter++;
        }

        if ((counter * hlen) < length)
        {
            itoosp(counter, c);

            digest.update(z, zoff, zlen);
            digest.update(c, 0, c.length);
            digest.dofinal(hashbuf, 0);

            system.arraycopy(hashbuf, 0, mask, counter * hlen, mask.length - (counter * hlen));
        }

        return mask;
    }
}
