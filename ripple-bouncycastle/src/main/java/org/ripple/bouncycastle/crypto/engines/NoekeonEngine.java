package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * a noekeon engine, using direct-key mode.
 */

public class noekeonengine
    implements blockcipher
{
    private static final int genericsize = 16; // block and key size, as well as the amount of rounds.
    
    private static final int[] nullvector = 
                               {
                                    0x00, 0x00, 0x00, 0x00 // used in decryption
                               },
        
                               roundconstants = 
                               {
                                    0x80, 0x1b, 0x36, 0x6c,
                                    0xd8, 0xab, 0x4d, 0x9a,
                                    0x2f, 0x5e, 0xbc, 0x63,
                                    0xc6, 0x97, 0x35, 0x6a,
                                    0xd4
                               };
    
    private int[] state   = new int[4], // a
                  subkeys = new int[4], // k
                  decryptkeys = new int[4];
    
    private boolean _initialised,
                    _forencryption;
    
    /**
     * create an instance of the noekeon encryption algorithm
     * and set some defaults
     */
    public noekeonengine()
    {
        _initialised = false;
    }
    
    public string getalgorithmname()
    {
        return "noekeon";
    }
    
    public int getblocksize()
    {
        return genericsize;
    }
    
    /**
     * initialise
     *
     * @param forencryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception illegalargumentexception if the params argument is
     * inappropriate.
     */
    public void init(
                     boolean             forencryption,
                     cipherparameters    params)
    {
        if (!(params instanceof keyparameter))
        {
            throw new illegalargumentexception("invalid parameter passed to noekeon init - " + params.getclass().getname());
        }
        
        _forencryption = forencryption;
        _initialised = true;
        
        keyparameter       p = (keyparameter)params;
        
        setkey(p.getkey());
    }
    
    public int processblock(
                            byte[]  in,
                            int     inoff,
                            byte[]  out,
                            int     outoff)
    {
        if (!_initialised)
        {
            throw new illegalstateexception(getalgorithmname()+" not initialised");
        }
        
        if ((inoff + genericsize) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }
        
        if ((outoff + genericsize) > out.length)
        {
            throw new outputlengthexception("output buffer too short");
        }
        
        return (_forencryption) ? encryptblock(in, inoff, out, outoff)
                                : decryptblock(in, inoff, out, outoff);
    }
    
    public void reset()
    {
    }
    
    /**
     * re-key the cipher.
     * <p>
     * @param  key  the key to be used
     */
    private void setkey(
                        byte[]      key)
    {
        subkeys[0] = bytestointbig(key, 0);
        subkeys[1] = bytestointbig(key, 4);
        subkeys[2] = bytestointbig(key, 8);
        subkeys[3] = bytestointbig(key, 12);
    }
    
    private int encryptblock(
                             byte[]  in,
                             int     inoff,
                             byte[]  out,
                             int     outoff)
    {
        state[0] = bytestointbig(in, inoff);
        state[1] = bytestointbig(in, inoff+4);
        state[2] = bytestointbig(in, inoff+8);
        state[3] = bytestointbig(in, inoff+12);
        
        int i;
        for (i = 0; i < genericsize; i++)
        {
            state[0] ^= roundconstants[i];
            theta(state, subkeys);
            pi1(state);
            gamma(state);
            pi2(state);            
        }
        
        state[0] ^= roundconstants[i];
        theta(state, subkeys);
        
        inttobytesbig(state[0], out, outoff);
        inttobytesbig(state[1], out, outoff+4);
        inttobytesbig(state[2], out, outoff+8);
        inttobytesbig(state[3], out, outoff+12);
        
        return genericsize;
    }
    
    private int decryptblock(
                             byte[]  in,
                             int     inoff,
                             byte[]  out,
                             int     outoff)
    {
        state[0] = bytestointbig(in, inoff);
        state[1] = bytestointbig(in, inoff+4);
        state[2] = bytestointbig(in, inoff+8);
        state[3] = bytestointbig(in, inoff+12);
        
        system.arraycopy(subkeys, 0, decryptkeys, 0, subkeys.length);
        theta(decryptkeys, nullvector);
        
        int i;
        for (i = genericsize; i > 0; i--)
        {
            theta(state, decryptkeys);
            state[0] ^= roundconstants[i];
            pi1(state);
            gamma(state);
            pi2(state);
        }
        
        theta(state, decryptkeys);
        state[0] ^= roundconstants[i];
        
        inttobytesbig(state[0], out, outoff);
        inttobytesbig(state[1], out, outoff+4);
        inttobytesbig(state[2], out, outoff+8);
        inttobytesbig(state[3], out, outoff+12);
        
        return genericsize;
    }
        
    private void gamma(int[] a)
    {
        a[1] ^= ~a[3] & ~a[2];
        a[0] ^= a[2] & a[1];
        
        int tmp = a[3];
        a[3]  = a[0];
        a[0]  = tmp;
        a[2] ^= a[0]^a[1]^a[3];
        
        a[1] ^= ~a[3] & ~a[2];
        a[0] ^= a[2] & a[1];
    }
    
    private void theta(int[] a, int[] k)
    {
        int tmp;
        
        tmp   = a[0]^a[2]; 
        tmp  ^= rotl(tmp,8)^rotl(tmp,24); 
        a[1] ^= tmp; 
        a[3] ^= tmp; 
        
        for (int i = 0; i < 4; i++)
        {
            a[i] ^= k[i];
        }
        
        tmp   = a[1]^a[3]; 
        tmp  ^= rotl(tmp,8)^rotl(tmp,24); 
        a[0] ^= tmp; 
        a[2] ^= tmp;
    }
    
    private void pi1(int[] a)
    {
        a[1] = rotl(a[1], 1);
        a[2] = rotl(a[2], 5);
        a[3] = rotl(a[3], 2);
    }
    
    private void pi2(int[] a)
    {
        a[1] = rotl(a[1], 31);
        a[2] = rotl(a[2], 27);
        a[3] = rotl(a[3], 30);
    }
    
    // helpers
    
    private int bytestointbig(byte[] in, int off)
    {
        return ((in[off++]) << 24) |
        ((in[off++] & 0xff) << 16) |
        ((in[off++] & 0xff) <<  8) |
         (in[off  ] & 0xff);
    }
    
    private void inttobytesbig(int x, byte[] out, int off)
    {
        out[off++] = (byte)(x >>> 24);
        out[off++] = (byte)(x >>> 16);
        out[off++] = (byte)(x >>>  8);
        out[off  ] = (byte)x;
    }
    
    private int rotl(int x, int y)
    {
        return (x << y) | (x >>> (32-y));
    }
}
