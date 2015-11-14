package org.ripple.bouncycastle.crypto.generators;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

/**
 * generator for pbe derived keys and ivs as defined by pkcs 12 v1.0.
 * <p>
 * the document this implementation is based on can be found at
 * <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html>
 * rsa's pkcs12 page</a>
 */
public class pkcs12parametersgenerator
    extends pbeparametersgenerator
{
    public static final int key_material = 1;
    public static final int iv_material  = 2;
    public static final int mac_material = 3;

    private digest digest;

    private int     u;
    private int     v;

    /**
     * construct a pkcs 12 parameters generator. this constructor will
     * accept any digest which also implements extendeddigest.
     *
     * @param digest the digest to be used as the source of derived keys.
     * @exception illegalargumentexception if an unknown digest is passed in.
     */
    public pkcs12parametersgenerator(
        digest  digest)
    {
        this.digest = digest;
        if (digest instanceof extendeddigest)
        {
            u = digest.getdigestsize();
            v = ((extendeddigest)digest).getbytelength();
        }
        else
        {
            throw new illegalargumentexception("digest " + digest.getalgorithmname() + " unsupported");
        }
    }

    /**
     * add a + b + 1, returning the result in a. the a value is treated
     * as a biginteger of length (b.length * 8) bits. the result is 
     * modulo 2^b.length in case of overflow.
     */
    private void adjust(
        byte[]  a,
        int     aoff,
        byte[]  b)
    {
        int  x = (b[b.length - 1] & 0xff) + (a[aoff + b.length - 1] & 0xff) + 1;

        a[aoff + b.length - 1] = (byte)x;
        x >>>= 8;

        for (int i = b.length - 2; i >= 0; i--)
        {
            x += (b[i] & 0xff) + (a[aoff + i] & 0xff);
            a[aoff + i] = (byte)x;
            x >>>= 8;
        }
    }

    /**
     * generation of a derived key ala pkcs12 v1.0.
     */
    private byte[] generatederivedkey(
        int idbyte,
        int n)
    {
        byte[]  d = new byte[v];
        byte[]  dkey = new byte[n];

        for (int i = 0; i != d.length; i++)
        {
            d[i] = (byte)idbyte;
        }

        byte[]  s;

        if ((salt != null) && (salt.length != 0))
        {
            s = new byte[v * ((salt.length + v - 1) / v)];

            for (int i = 0; i != s.length; i++)
            {
                s[i] = salt[i % salt.length];
            }
        }
        else
        {
            s = new byte[0];
        }

        byte[]  p;

        if ((password != null) && (password.length != 0))
        {
            p = new byte[v * ((password.length + v - 1) / v)];

            for (int i = 0; i != p.length; i++)
            {
                p[i] = password[i % password.length];
            }
        }
        else
        {
            p = new byte[0];
        }

        byte[]  i = new byte[s.length + p.length];

        system.arraycopy(s, 0, i, 0, s.length);
        system.arraycopy(p, 0, i, s.length, p.length);

        byte[]  b = new byte[v];
        int     c = (n + u - 1) / u;
        byte[]  a = new byte[u];

        for (int i = 1; i <= c; i++)
        {
            digest.update(d, 0, d.length);
            digest.update(i, 0, i.length);
            digest.dofinal(a, 0);
            for (int j = 1; j < iterationcount; j++)
            {
                digest.update(a, 0, a.length);
                digest.dofinal(a, 0);
            }

            for (int j = 0; j != b.length; j++)
            {
                b[j] = a[j % a.length];
            }

            for (int j = 0; j != i.length / v; j++)
            {
                adjust(i, j * v, b);
            }

            if (i == c)
            {
                system.arraycopy(a, 0, dkey, (i - 1) * u, dkey.length - ((i - 1) * u));
            }
            else
            {
                system.arraycopy(a, 0, dkey, (i - 1) * u, a.length);
            }
        }

        return dkey;
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

        byte[]  dkey = generatederivedkey(key_material, keysize);

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

        byte[]  dkey = generatederivedkey(key_material, keysize);

        byte[]  iv = generatederivedkey(iv_material, ivsize);

        return new parameterswithiv(new keyparameter(dkey, 0, keysize), iv, 0, ivsize);
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
        keysize = keysize / 8;

        byte[]  dkey = generatederivedkey(mac_material, keysize);

        return new keyparameter(dkey, 0, keysize);
    }
}
