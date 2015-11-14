package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.params.keyparameter;

/**
 * hmac implementation based on rfc2104
 *
 * h(k xor opad, h(k xor ipad, text))
 */
public class oldhmac
implements mac
{
    private final static int block_length = 64;

    private final static byte ipad = (byte)0x36;
    private final static byte opad = (byte)0x5c;

    private digest digest;
    private int digestsize;
    private byte[] inputpad = new byte[block_length];
    private byte[] outputpad = new byte[block_length];

    /**
     * @deprecated uses incorrect pad for sha-512 and sha-384 use hmac.
     */
    public oldhmac(
        digest digest)
    {
        this.digest = digest;
        digestsize = digest.getdigestsize();
    }

    public string getalgorithmname()
    {
        return digest.getalgorithmname() + "/hmac";
    }

    public digest getunderlyingdigest()
    {
        return digest;
    }

    public void init(
        cipherparameters params)
    {
        digest.reset();

        byte[] key = ((keyparameter)params).getkey();

        if (key.length > block_length)
        {
            digest.update(key, 0, key.length);
            digest.dofinal(inputpad, 0);
            for (int i = digestsize; i < inputpad.length; i++)
            {
                inputpad[i] = 0;
            }
        }
        else
        {
            system.arraycopy(key, 0, inputpad, 0, key.length);
            for (int i = key.length; i < inputpad.length; i++)
            {
                inputpad[i] = 0;
            }
        }

        outputpad = new byte[inputpad.length];
        system.arraycopy(inputpad, 0, outputpad, 0, inputpad.length);

        for (int i = 0; i < inputpad.length; i++)
        {
            inputpad[i] ^= ipad;
        }

        for (int i = 0; i < outputpad.length; i++)
        {
            outputpad[i] ^= opad;
        }

        digest.update(inputpad, 0, inputpad.length);
    }

    public int getmacsize()
    {
        return digestsize;
    }

    public void update(
        byte in)
    {
        digest.update(in);
    }

    public void update(
        byte[] in,
        int inoff,
        int len)
    {
        digest.update(in, inoff, len);
    }

    public int dofinal(
        byte[] out,
        int outoff)
    {
        byte[] tmp = new byte[digestsize];
        digest.dofinal(tmp, 0);

        digest.update(outputpad, 0, outputpad.length);
        digest.update(tmp, 0, tmp.length);

        int     len = digest.dofinal(out, outoff);

        reset();

        return len;
    }

    /**
     * reset the mac generator.
     */
    public void reset()
    {
        /*
         * reset the underlying digest.
         */
        digest.reset();

        /*
         * reinitialize the digest.
         */
        digest.update(inputpad, 0, inputpad.length);
    }
}
