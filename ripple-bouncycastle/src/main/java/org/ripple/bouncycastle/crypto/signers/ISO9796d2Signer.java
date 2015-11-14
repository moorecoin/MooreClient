package org.ripple.bouncycastle.crypto.signers;

import java.util.hashtable;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.signerwithrecovery;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;

/**
 * iso9796-2 - mechanism using a hash function with recovery (scheme 1)
 */
public class iso9796d2signer
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

    private static hashtable  trailermap          = new hashtable();

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

    private digest                      digest;
    private asymmetricblockcipher       cipher;

    private int         trailer;
    private int         keybits;
    private byte[]      block;
    private byte[]      mbuf;
    private int         messagelength;
    private boolean     fullmessage;
    private byte[]      recoveredmessage;

    private byte[]      presig;
    private byte[]      preblock;

    /**
     * generate a signer for the with either implicit or explicit trailers
     * for iso9796-2.
     * 
     * @param cipher base cipher to use for signature creation/verification
     * @param digest digest to use.
     * @param implicit whether or not the trailer is implicit or gives the hash.
     */
    public iso9796d2signer(
        asymmetricblockcipher   cipher,
        digest                  digest,
        boolean                 implicit)
    {
        this.cipher = cipher;
        this.digest = digest;

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
     * @param cipher cipher to use.
     * @param digest digest to sign with.
     */
    public iso9796d2signer(
        asymmetricblockcipher   cipher,
        digest                  digest)
    {
        this(cipher, digest, false);
    }
    
    public void init(
        boolean                 forsigning,
        cipherparameters        param)
    {
        rsakeyparameters  kparam = (rsakeyparameters)param;

        cipher.init(forsigning, kparam);

        keybits = kparam.getmodulus().bitlength();

        block = new byte[(keybits + 7) / 8];
        
        if (trailer == trailer_implicit)
        {
            mbuf = new byte[block.length - digest.getdigestsize() - 2];
        }
        else
        {
            mbuf = new byte[block.length - digest.getdigestsize() - 3];
        }

        reset();
    }

    /**
     * compare two byte arrays - constant time
     */
    private boolean issameas(
        byte[]    a,
        byte[]    b)
    {
        boolean isokay = true;

        if (messagelength > mbuf.length)
        {
            if (mbuf.length > b.length)
            {
                isokay = false;
            }
            
            for (int i = 0; i != mbuf.length; i++)
            {
                if (a[i] != b[i])
                {
                    isokay = false;
                }
            }
        }
        else
        {
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
        }
        
        return isokay;
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

    public void updatewithrecoveredmessage(byte[] signature)
        throws invalidciphertextexception
    {
        byte[]      block = cipher.processblock(signature, 0, signature.length);

        if (((block[0] & 0xc0) ^ 0x40) != 0)
        {
            throw new invalidciphertextexception("malformed signature");
        }

        if (((block[block.length - 1] & 0xf) ^ 0xc) != 0)
        {
            throw new invalidciphertextexception("malformed signature");
        }

        int     delta = 0;

        if (((block[block.length - 1] & 0xff) ^ 0xbc) == 0)
        {
            delta = 1;
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

            delta = 2;
        }

        //
        // find out how much padding we've got
        //
        int mstart = 0;

        for (mstart = 0; mstart != block.length; mstart++)
        {
            if (((block[mstart] & 0x0f) ^ 0x0a) == 0)
            {
                break;
            }
        }

        mstart++;

        int off = block.length - delta - digest.getdigestsize();

        //
        // there must be at least one byte of message string
        //
        if ((off - mstart) <= 0)
        {
            throw new invalidciphertextexception("malformed block");
        }

        //
        // if we contain the whole message as well, check the hash of that.
        //
        if ((block[0] & 0x20) == 0)
        {
            fullmessage = true;

            recoveredmessage = new byte[off - mstart];
            system.arraycopy(block, mstart, recoveredmessage, 0, recoveredmessage.length);
        }
        else
        {
            fullmessage = false;

            recoveredmessage = new byte[off - mstart];
            system.arraycopy(block, mstart, recoveredmessage, 0, recoveredmessage.length);
        }

        presig = signature;
        preblock = block;

        digest.update(recoveredmessage, 0, recoveredmessage.length);
        messagelength = recoveredmessage.length;
        system.arraycopy(recoveredmessage, 0, mbuf, 0, recoveredmessage.length);
    }
    
    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte    b)
    {
        digest.update(b);

        if (messagelength < mbuf.length)
        {
            mbuf[messagelength] = b;
        }

        messagelength++;
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  in,
        int     off,
        int     len)
    {
        while (len > 0 && messagelength < mbuf.length)
        {
            this.update(in[off]);
            off++;
            len--;
        }

        digest.update(in, off, len);
        messagelength += len;
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
        messagelength = 0;
        clearblock(mbuf);
        
        if (recoveredmessage != null)
        {
            clearblock(recoveredmessage);
        }
        
        recoveredmessage = null;
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
        int     digsize = digest.getdigestsize();

        int t = 0;
        int delta = 0;

        if (trailer == trailer_implicit)
        {
            t = 8;
            delta = block.length - digsize - 1;
            digest.dofinal(block, delta);
            block[block.length - 1] = (byte)trailer_implicit;
        }
        else
        {
            t = 16;
            delta = block.length - digsize - 2;
            digest.dofinal(block, delta);
            block[block.length - 2] = (byte)(trailer >>> 8);
            block[block.length - 1] = (byte)trailer;
        }

        byte    header = 0;
        int     x = (digsize + messagelength) * 8 + t + 4 - keybits;

        if (x > 0)
        {
            int mr = messagelength - ((x + 7) / 8);
            header = 0x60;

            delta -= mr;
            
            system.arraycopy(mbuf, 0, block, delta, mr);
        }
        else
        {
            header = 0x40;
            delta -= messagelength;
            
            system.arraycopy(mbuf, 0, block, delta, messagelength);
        }
        
        if ((delta - 1) > 0)
        {
            for (int i = delta - 1; i != 0; i--)
            {
                block[i] = (byte)0xbb;
            }
            block[delta - 1] ^= (byte)0x01;
            block[0] = (byte)0x0b;
            block[0] |= header;
        }
        else
        {
            block[0] = (byte)0x0a;
            block[0] |= header;
        }

        byte[]  b = cipher.processblock(block, 0, block.length);

        clearblock(mbuf);
        clearblock(block);

        return b;
    }

    /**
     * return true if the signature represents a iso9796-2 signature
     * for the passed in message.
     */
    public boolean verifysignature(
        byte[]      signature)
    {
        byte[]      block = null;

        if (presig == null)
        {
            try
            {
                block = cipher.processblock(signature, 0, signature.length);
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

            block = preblock;

            presig = null;
            preblock = null;
        }

        if (((block[0] & 0xc0) ^ 0x40) != 0)
        {
            return returnfalse(block);
        }

        if (((block[block.length - 1] & 0xf) ^ 0xc) != 0)
        {
            return returnfalse(block);
        }

        int     delta = 0;

        if (((block[block.length - 1] & 0xff) ^ 0xbc) == 0)
        {
            delta = 1;
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

            delta = 2;
        }

        //
        // find out how much padding we've got
        //
        int mstart = 0;

        for (mstart = 0; mstart != block.length; mstart++)
        {
            if (((block[mstart] & 0x0f) ^ 0x0a) == 0)
            {
                break;
            }
        }

        mstart++;

        //
        // check the hashes
        //
        byte[]  hash = new byte[digest.getdigestsize()];

        int off = block.length - delta - hash.length;

        //
        // there must be at least one byte of message string
        //
        if ((off - mstart) <= 0)
        {
            return returnfalse(block);
        }

        //
        // if we contain the whole message as well, check the hash of that.
        //
        if ((block[0] & 0x20) == 0)
        {
            fullmessage = true;

            // check right number of bytes passed in.
            if (messagelength > off - mstart)
            {
                return returnfalse(block);
            }
            
            digest.reset();
            digest.update(block, mstart, off - mstart);
            digest.dofinal(hash, 0);

            boolean isokay = true;

            for (int i = 0; i != hash.length; i++)
            {
                block[off + i] ^= hash[i];
                if (block[off + i] != 0)
                {
                    isokay = false;
                }
            }

            if (!isokay)
            {
                return returnfalse(block);
            }

            recoveredmessage = new byte[off - mstart];
            system.arraycopy(block, mstart, recoveredmessage, 0, recoveredmessage.length);
        }
        else
        {
            fullmessage = false;
            
            digest.dofinal(hash, 0);

            boolean isokay = true;

            for (int i = 0; i != hash.length; i++)
            {
                block[off + i] ^= hash[i];
                if (block[off + i] != 0)
                {
                    isokay = false;
                }
            }

            if (!isokay)
            {
                return returnfalse(block);
            }

            recoveredmessage = new byte[off - mstart];
            system.arraycopy(block, mstart, recoveredmessage, 0, recoveredmessage.length);
        }

        //
        // if they've input a message check what we've recovered against
        // what was input.
        //
        if (messagelength != 0)
        {
            if (!issameas(mbuf, recoveredmessage))
            {
                return returnfalse(block);
            }
        }
        
        clearblock(mbuf);
        clearblock(block);

        return true;
    }

    private boolean returnfalse(byte[] block)
    {
        clearblock(mbuf);
        clearblock(block);

        return false;
    }

    /**
     * return true if the full message was recoveredmessage.
     * 
     * @return true on full message recovery, false otherwise.
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
}
