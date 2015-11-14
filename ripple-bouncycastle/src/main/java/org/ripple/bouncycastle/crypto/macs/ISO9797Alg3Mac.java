package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.engines.desengine;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.paddings.blockcipherpadding;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * des based cbc block cipher mac according to iso9797, algorithm 3 (ansi x9.19 retail mac)
 *
 * this could as well be derived from cbcblockciphermac, but then the property mac in the base
 * class must be changed to protected  
 */

public class iso9797alg3mac 
    implements mac 
{
    private byte[]              mac;
    
    private byte[]              buf;
    private int                 bufoff;
    private blockcipher         cipher;
    private blockcipherpadding  padding;
    
    private int                 macsize;
    private keyparameter        lastkey2;
    private keyparameter        lastkey3;
    
    /**
     * create a retail-mac based on a cbc block cipher. this will produce an
     * authentication code of the length of the block size of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the mac generation. this must
     * be desengine.
     */
    public iso9797alg3mac(
            blockcipher     cipher)
    {
        this(cipher, cipher.getblocksize() * 8, null);
    }
    
    /**
     * create a retail-mac based on a cbc block cipher. this will produce an
     * authentication code of the length of the block size of the cipher.
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     * @param padding the padding to be used to complete the last block.
     */
    public iso9797alg3mac(
        blockcipher         cipher,
        blockcipherpadding  padding)
    {
        this(cipher, cipher.getblocksize() * 8, padding);
    }

    /**
     * create a retail-mac based on a block cipher with the size of the
     * mac been given in bits. this class uses single des cbc mode as the basis for the
     * mac generation.
     * <p>
     * note: the size of the mac must be at least 24 bits (fips publication 81),
     * or 16 bits if being used as a data authenticator (fips publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see handbook of applied cryptography).
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     * @param macsizeinbits the size of the mac in bits, must be a multiple of 8.
     */
    public iso9797alg3mac(
        blockcipher     cipher,
        int             macsizeinbits)
    {
        this(cipher, macsizeinbits, null);
    }

    /**
     * create a standard mac based on a block cipher with the size of the
     * mac been given in bits. this class uses single des cbc mode as the basis for the
     * mac generation. the final block is decrypted and then encrypted using the
     * middle and right part of the key.
     * <p>
     * note: the size of the mac must be at least 24 bits (fips publication 81),
     * or 16 bits if being used as a data authenticator (fips publication 113),
     * and in general should be less than the size of the block cipher as it reduces
     * the chance of an exhaustive attack (see handbook of applied cryptography).
     *
     * @param cipher the cipher to be used as the basis of the mac generation.
     * @param macsizeinbits the size of the mac in bits, must be a multiple of 8.
     * @param padding the padding to be used to complete the last block.
     */
    public iso9797alg3mac(
        blockcipher         cipher,
        int                 macsizeinbits,
        blockcipherpadding  padding)
    {
        if ((macsizeinbits % 8) != 0)
        {
            throw new illegalargumentexception("mac size must be multiple of 8");
        }

        if (!(cipher instanceof desengine))
        {
            throw new illegalargumentexception("cipher must be instance of desengine");
        }

        this.cipher = new cbcblockcipher(cipher);
        this.padding = padding;
        this.macsize = macsizeinbits / 8;

        mac = new byte[cipher.getblocksize()];

        buf = new byte[cipher.getblocksize()];
        bufoff = 0;
    }
    
    public string getalgorithmname()
    {
        return "iso9797alg3";
    }

    public void init(cipherparameters params)
    {
        reset();

        if (!(params instanceof keyparameter || params instanceof parameterswithiv))
        {
            throw new illegalargumentexception(
                    "params must be an instance of keyparameter or parameterswithiv");
        }

        // keyparameter must contain a double or triple length des key,
        // however the underlying cipher is a single des. the middle and
        // right key are used only in the final step.

        keyparameter kp;

        if (params instanceof keyparameter)
        {
            kp = (keyparameter)params;
        }
        else
        {
            kp = (keyparameter)((parameterswithiv)params).getparameters();
        }

        keyparameter key1;
        byte[] keyvalue = kp.getkey();

        if (keyvalue.length == 16)
        { // double length des key
            key1 = new keyparameter(keyvalue, 0, 8);
            this.lastkey2 = new keyparameter(keyvalue, 8, 8);
            this.lastkey3 = key1;
        }
        else if (keyvalue.length == 24)
        { // triple length des key
            key1 = new keyparameter(keyvalue, 0, 8);
            this.lastkey2 = new keyparameter(keyvalue, 8, 8);
            this.lastkey3 = new keyparameter(keyvalue, 16, 8);
        }
        else
        {
            throw new illegalargumentexception(
                    "key must be either 112 or 168 bit long");
        }

        if (params instanceof parameterswithiv)
        {
            cipher.init(true, new parameterswithiv(key1, ((parameterswithiv)params).getiv()));
        }
        else
        {
            cipher.init(true, key1);
        }
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
        
        if (padding == null)
        {
            //
            // pad with zeroes
            //
            while (bufoff < blocksize)
            {
                buf[bufoff] = 0;
                bufoff++;
            }
        }
        else
        {
            if (bufoff == blocksize)
            {
                cipher.processblock(buf, 0, mac, 0);
                bufoff = 0;
            }
            
            padding.addpadding(buf, bufoff);
        }
        
        cipher.processblock(buf, 0, mac, 0);

        // added to code from base class
        desengine deseng = new desengine();
        
        deseng.init(false, this.lastkey2);
        deseng.processblock(mac, 0, mac, 0);
        
        deseng.init(true, this.lastkey3);
        deseng.processblock(mac, 0, mac, 0);
        // ****
        
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
