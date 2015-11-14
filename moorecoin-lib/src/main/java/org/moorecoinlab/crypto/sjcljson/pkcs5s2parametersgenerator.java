package org.moorecoinlab.crypto.sjcljson;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * generator for pbe derived keys and ivs as defined by pkcs 5 v2.0 scheme 2.
 * this generator uses a sha-1 hmac as the calculation function.
 * <p>
 * the document this implementation is based on can be found at
 * <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html>
 * rsa's pkcs5 page</a>
 */
public class pkcs5s2parametersgenerator
    extends pbeparametersgenerator
{
    private mac hmac;
    private byte[] state;

    /**
     * construct a pkcs5 scheme 2 parameters generator.
     */
    public pkcs5s2parametersgenerator()
    {
        this(new sha1digest());
    }

    public pkcs5s2parametersgenerator(digest digest)
    {
        hmac = new hmac(digest);
        state = new byte[hmac.getmacsize()];
    }

    private void f(
        byte[]  s,
        int     c,
        byte[]  ibuf,
        byte[]  out,
        int     outoff)
    {
        if (c == 0)
        {
            throw new illegalargumentexception("iteration count must be at least 1.");
        }

        if (s != null)
        {
            hmac.update(s, 0, s.length);
        }

        hmac.update(ibuf, 0, ibuf.length);
        hmac.dofinal(state, 0);

        system.arraycopy(state, 0, out, outoff, state.length);
        
        for (int count = 1; count < c; count++)
        {
            hmac.update(state, 0, state.length);
            hmac.dofinal(state, 0);

            for (int j = 0; j != state.length; j++)
            {
                out[outoff + j] ^= state[j];
            }
        }
    }

    private byte[] generatederivedkey(
        int dklen)
    {
        int     hlen = hmac.getmacsize();
        int     l = (dklen + hlen - 1) / hlen;
        byte[]  ibuf = new byte[4];
        byte[]  outbytes = new byte[l * hlen];
        int     outpos = 0;

        cipherparameters param = new keyparameter(password);

        hmac.init(param);

        for (int i = 1; i <= l; i++)
        {
            // increment the value in 'ibuf'
            int pos = 3;
            while (++ibuf[pos] == 0)
            {
                --pos;
            }

            f(salt, iterationcount, ibuf, outbytes, outpos);
            outpos += hlen;
        }

        return outbytes;
    }

    /**
     * generate a key parameter derived from the password, salt, and iteration
     * count we are currently initialised with.
     *
     * @param keysize the size of the key we want (in bits)
     * @return a keyparameter object.
     */
    public cipherparameters generatederivedparameters(
        int keysize)
    {
        keysize = keysize / 8;

        byte[]  dkey = generatederivedkey(keysize);

        return new keyparameter(dkey, 0, keysize);
    }

    /**
     * generate a key with initialisation vector parameter derived from
     * the password, salt, and iteration count we are currently initialised
     * with.
     *
     * @param keysize the size of the key we want (in bits)
     * @param ivsize the size of the iv we want (in bits)
     * @return a parameterswithiv object.
     */
    public cipherparameters generatederivedparameters(
        int     keysize,
        int     ivsize)
    {
        keysize = keysize / 8;
        ivsize = ivsize / 8;

        byte[]  dkey = generatederivedkey(keysize + ivsize);

        return new parameterswithiv(new keyparameter(dkey, 0, keysize), dkey, keysize, ivsize);
    }

    /**
     * generate a key parameter for use with a mac derived from the password,
     * salt, and iteration count we are currently initialised with.
     *
     * @param keysize the size of the key we want (in bits)
     * @return a keyparameter object.
     */
    public cipherparameters generatederivedmacparameters(
        int keysize)
    {
        return generatederivedparameters(keysize);
    }
}
