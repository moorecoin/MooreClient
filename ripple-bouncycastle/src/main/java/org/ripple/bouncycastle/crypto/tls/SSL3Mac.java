package org.ripple.bouncycastle.crypto.tls;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.util.arrays;

/**
 * hmac implementation based on original internet draft for hmac (rfc 2104)
 * <p/>
 * the difference is that padding is concatenated versus xored with the key
 * <p/>
 * h(k + opad, h(k + ipad, text))
 */
public class ssl3mac
    implements mac
{
    private final static byte ipad_byte = (byte)0x36;
    private final static byte opad_byte = (byte)0x5c;

    static final byte[] ipad = genpad(ipad_byte, 48);
    static final byte[] opad = genpad(opad_byte, 48);

    private digest digest;

    private byte[] secret;
    private int padlength;

    /**
     * base constructor for one of the standard digest algorithms that the bytelength of
     * the algorithm is know for. behaviour is undefined for digests other than md5 or sha1.
     *
     * @param digest the digest.
     */
    public ssl3mac(digest digest)
    {
        this.digest = digest;

        if (digest.getdigestsize() == 20)
        {
            this.padlength = 40;
        }
        else
        {
            this.padlength = 48;
        }
    }

    public string getalgorithmname()
    {
        return digest.getalgorithmname() + "/ssl3mac";
    }

    public digest getunderlyingdigest()
    {
        return digest;
    }

    public void init(cipherparameters params)
    {
        secret = arrays.clone(((keyparameter)params).getkey());

        reset();
    }

    public int getmacsize()
    {
        return digest.getdigestsize();
    }

    public void update(byte in)
    {
        digest.update(in);
    }

    public void update(byte[] in, int inoff, int len)
    {
        digest.update(in, inoff, len);
    }

    public int dofinal(byte[] out, int outoff)
    {
        byte[] tmp = new byte[digest.getdigestsize()];
        digest.dofinal(tmp, 0);

        digest.update(secret, 0, secret.length);
        digest.update(opad, 0, padlength);
        digest.update(tmp, 0, tmp.length);

        int len = digest.dofinal(out, outoff);

        reset();

        return len;
    }

    /**
     * reset the mac generator.
     */
    public void reset()
    {
        digest.reset();
        digest.update(secret, 0, secret.length);
        digest.update(ipad, 0, padlength);
    }

    private static byte[] genpad(byte b, int count)
    {
        byte[] padding = new byte[count];
        arrays.fill(padding, b);
        return padding;
    }
}
