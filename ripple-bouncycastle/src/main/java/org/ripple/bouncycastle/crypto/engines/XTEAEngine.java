package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.outputlengthexception;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * an xtea engine.
 */
public class xteaengine
    implements blockcipher
{
    private static final int rounds     = 32,
                             block_size = 8,
//                             key_size   = 16,
                             delta      = 0x9e3779b9;

    /*
     * the expanded key array of 4 subkeys
     */
    private int[]   _s    = new int[4],
                    _sum0 = new int[32],
                    _sum1 = new int[32];
    private boolean _initialised,
                    _forencryption;

    /**
     * create an instance of the tea encryption algorithm
     * and set some defaults
     */
    public xteaengine()
    {
        _initialised = false;
    }

    public string getalgorithmname()
    {
        return "xtea";
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
        int i, j;
        for (i = j = 0; i < 4; i++,j+=4)
        {
            _s[i] = bytestoint(key, j);
        }
            
        for (i = j = 0; i < rounds; i++)
        {
                _sum0[i] = (j + _s[j & 3]);
                j += delta;
                _sum1[i] = (j + _s[j >>> 11 & 3]);
        }
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

        for (int i = 0; i < rounds; i++)
        {
            v0    += ((v1 << 4 ^ v1 >>> 5) + v1) ^ _sum0[i];
            v1    += ((v0 << 4 ^ v0 >>> 5) + v0) ^ _sum1[i];
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

        for (int i = rounds-1; i >= 0; i--)
        {
            v1  -= ((v0 << 4 ^ v0 >>> 5) + v0) ^ _sum1[i];
            v0  -= ((v1 << 4 ^ v1 >>> 5) + v1) ^ _sum0[i];
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
