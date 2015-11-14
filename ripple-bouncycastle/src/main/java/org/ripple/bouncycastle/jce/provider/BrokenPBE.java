package org.ripple.bouncycastle.jce.provider;

import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.pbeparameterspec;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.ripemd160digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.generators.pkcs12parametersgenerator;
import org.ripple.bouncycastle.crypto.generators.pkcs5s1parametersgenerator;
import org.ripple.bouncycastle.crypto.generators.pkcs5s2parametersgenerator;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.bcpbekey;

/**
 * generator for pbe derived keys and ivs as defined by pkcs 12 v1.0,
 * with a bug affecting 180 bit plus keys - this class is only here to
 * allow smooth migration of the version 0 keystore to version 1. don't
 * use it (it won't be staying around).
 * <p>
 * the document this implementation is based on can be found at
 * <a href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html>
 * rsa's pkcs12 page</a>
 */
class oldpkcs12parametersgenerator
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
     * accept md5, sha1, and ripemd160.
     *
     * @param digest the digest to be used as the source of derived keys.
     * @exception illegalargumentexception if an unknown digest is passed in.
     */
    public oldpkcs12parametersgenerator(
        digest  digest)
    {
        this.digest = digest;
        if (digest instanceof md5digest)
        {
            u = 128 / 8;
            v = 512 / 8;
        }
        else if (digest instanceof sha1digest)
        {
            u = 160 / 8;
            v = 512 / 8;
        }
        else if (digest instanceof ripemd160digest)
        {
            u = 160 / 8;
            v = 512 / 8;
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

        for (int i = 1; i <= c; i++)
        {
            byte[]  a = new byte[u];

            digest.update(d, 0, d.length);
            digest.update(i, 0, i.length);
            digest.dofinal(a, 0);
            for (int j = 1; j != iterationcount; j++)
            {
                digest.update(a, 0, a.length);
                digest.dofinal(a, 0);
            }

            for (int j = 0; j != b.length; j++)
            {
                b[i] = a[j % a.length];
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

public interface brokenpbe
{
    //
    // pbe based encryption constants - by default we do pkcs12 with sha-1
    //
    static final int        md5         = 0;
    static final int        sha1        = 1;
    static final int        ripemd160   = 2;

    static final int        pkcs5s1     = 0;
    static final int        pkcs5s2     = 1;
    static final int        pkcs12      = 2;
    static final int        old_pkcs12  = 3;

    /**
     * uses the appropriate mixer to generate the key and iv if neccessary.
     */
    static class util
    {
        /**
         * a faulty parity routine...
         *
         * @param bytes the byte array to set the parity on.
         */
        static private void setoddparity(
            byte[] bytes)
        {
            for (int i = 0; i < bytes.length; i++)
            {
                int b = bytes[i];
                bytes[i] = (byte)((b & 0xfe) |
                                (((b >> 1) ^
                                (b >> 2) ^
                                (b >> 3) ^
                                (b >> 4) ^
                                (b >> 5) ^
                                (b >> 6) ^
                                (b >> 7)) ^ 0x01));
            }
        }

        static private pbeparametersgenerator makepbegenerator(
            int                     type,
            int                     hash)
        {
            pbeparametersgenerator  generator;
    
            if (type == pkcs5s1)
            {
                switch (hash)
                {
                case md5:
                    generator = new pkcs5s1parametersgenerator(new md5digest());
                    break;
                case sha1:
                    generator = new pkcs5s1parametersgenerator(new sha1digest());
                    break;
                default:
                    throw new illegalstateexception("pkcs5 scheme 1 only supports only md5 and sha1.");
                }
            }
            else if (type == pkcs5s2)
            {
                generator = new pkcs5s2parametersgenerator();
            }
            else if (type == old_pkcs12)
            {
                switch (hash)
                {
                case md5:
                    generator = new oldpkcs12parametersgenerator(new md5digest());
                    break;
                case sha1:
                    generator = new oldpkcs12parametersgenerator(new sha1digest());
                    break;
                case ripemd160:
                    generator = new oldpkcs12parametersgenerator(new ripemd160digest());
                    break;
                default:
                    throw new illegalstateexception("unknown digest scheme for pbe encryption.");
                }
            }
            else
            {
                switch (hash)
                {
                case md5:
                    generator = new pkcs12parametersgenerator(new md5digest());
                    break;
                case sha1:
                    generator = new pkcs12parametersgenerator(new sha1digest());
                    break;
                case ripemd160:
                    generator = new pkcs12parametersgenerator(new ripemd160digest());
                    break;
                default:
                    throw new illegalstateexception("unknown digest scheme for pbe encryption.");
                }
            }
    
            return generator;
        }

        /**
         * construct a key and iv (if neccessary) suitable for use with a 
         * cipher.
         */
        static cipherparameters makepbeparameters(
            bcpbekey pbekey,
            algorithmparameterspec  spec,
            int                     type,
            int                     hash,
            string                  targetalgorithm,
            int                     keysize,
            int                     ivsize)
        {
            if ((spec == null) || !(spec instanceof pbeparameterspec))
            {
                throw new illegalargumentexception("need a pbeparameter spec with a pbe key.");
            }
    
            pbeparameterspec        pbeparam = (pbeparameterspec)spec;
            pbeparametersgenerator  generator = makepbegenerator(type, hash);
            byte[]                  key = pbekey.getencoded();
            cipherparameters        param;
    
            generator.init(key, pbeparam.getsalt(), pbeparam.getiterationcount());

            if (ivsize != 0)
            {
                param = generator.generatederivedparameters(keysize, ivsize);
            }
            else
            {
                param = generator.generatederivedparameters(keysize);
            }

            if (targetalgorithm.startswith("des"))
            {
                if (param instanceof parameterswithiv)
                {
                    keyparameter    kparam = (keyparameter)((parameterswithiv)param).getparameters();

                    setoddparity(kparam.getkey());
                }
                else
                {
                    keyparameter    kparam = (keyparameter)param;

                    setoddparity(kparam.getkey());
                }
            }

            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }

            return param;
        }

        /**
         * generate a pbe based key suitable for a mac algorithm, the
         * key size is chosen according the mac size, or the hashing algorithm,
         * whichever is greater.
         */
        static cipherparameters makepbemacparameters(
            bcpbekey pbekey,
            algorithmparameterspec  spec,
            int                     type,
            int                     hash,
            int                     keysize)
        {
            if ((spec == null) || !(spec instanceof pbeparameterspec))
            {
                throw new illegalargumentexception("need a pbeparameter spec with a pbe key.");
            }
    
            pbeparameterspec        pbeparam = (pbeparameterspec)spec;
            pbeparametersgenerator  generator = makepbegenerator(type, hash);
            byte[]                  key = pbekey.getencoded();
            cipherparameters        param;
    
            generator.init(key, pbeparam.getsalt(), pbeparam.getiterationcount());

            param = generator.generatederivedmacparameters(keysize);
    
            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }

            return param;
        }
    }
}
