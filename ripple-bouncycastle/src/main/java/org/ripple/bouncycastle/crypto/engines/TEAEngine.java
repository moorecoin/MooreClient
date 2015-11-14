package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * an tea engine.
 */
public class teaengine
    implements blockcipher
{
    private static final int rounds     = 32,
                             block_size = 8,
//                             key_size   = 16,
                             delta      = 0x9e3779b9,
                             d_sum      = 0xc6ef3720; // sum on decrypt
    /*
     * the expanded key array of 4 subkeys
     */
    private int _a, _b, _c, _d;
    private boolean _initialised;
    private boolean _forencryption;

    /**
     * create an instance of the tea encryption algorithm
     * and set some defaults
     */
    public teaengine()
    {
        _initialised = false;
    }

    public string getalgorithmname()
    {
        return "tea";
    }

    public int getblocksize()
    {
        return block_size;
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
            throw new illegalargumentexception("invalid parameter passed to tea init - " + params.getclass().getname());
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
        
        if ((inoff + block_size) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }
        
        if ((outoff + block_size) > out.length)
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
        _a = bytestoint(key, 0);
        _b = bytestoint(key, 4);
        _c = bytestoint(key, 8);
        _d = bytestoint(key, 12);
    }

    private int encryptblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        // pack bytes into integers
        int v0 = bytestoint(in, inoff);
        int v1 = bytestoint(in, inoff + 4);
        
        int sum = 0;
        
        for (int i = 0; i != rounds; i++)
        {
            sum += delta;
            v0  += ((v1 << 4) + _a) ^ (v1 + sum) ^ ((v1 >>> 5) + _b);
            v1  += ((v0 << 4) + _c) ^ (v0 + sum) ^ ((v0 >>> 5) + _d);
        }

        unpackint(v0, out, outoff);
        unpackint(v1, out, outoff + 4);
        
        return block_size;
    }

    private int decryptblock(
        byte[]  in,
        int     inoff,
        byte[]  out,
        int     outoff)
    {
        // pack bytes into integers
        int v0 = bytestoint(in, inoff);
        int v1 = bytestoint(in, inoff + 4);
        
        int sum = d_sum;
        
        for (int i = 0; i != rounds; i++)
        {
            v1  -= ((v0 << 4) + _c) ^ (v0 + sum) ^ ((v0 >>> 5) + _d);
            v0  -= ((v1 << 4) + _a) ^ (v1 + sum) ^ ((v1 >>> 5) + _b);
            sum -= delta;
        }
        
        unpackint(v0, out, outoff);
        unpackint(v1, out, outoff + 4);
        
        return block_size;
    }

    private int bytestoint(byte[] in, int inoff)
    {
        return ((in[inoff++]) << 24) |
                 ((in[inoff++] & 255) << 16) |
                 ((in[inoff++] & 255) <<  8) |
                 ((in[inoff] & 255));
    }

    private void unpackint(int v, byte[] out, int outoff)
    {
        out[outoff++] = (byte)(v >>> 24);
        out[outoff++] = (byte)(v >>> 16);
        out[outoff++] = (byte)(v >>>  8);
        out[outoff  ] = (byte)v;
    }
}
