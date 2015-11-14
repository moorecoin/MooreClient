package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.pbekeyspec;
import javax.crypto.spec.pbeparameterspec;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.digests.gost3411digest;
import org.ripple.bouncycastle.crypto.digests.md2digest;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.ripemd160digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.tigerdigest;
import org.ripple.bouncycastle.crypto.generators.opensslpbeparametersgenerator;
import org.ripple.bouncycastle.crypto.generators.pkcs12parametersgenerator;
import org.ripple.bouncycastle.crypto.generators.pkcs5s1parametersgenerator;
import org.ripple.bouncycastle.crypto.generators.pkcs5s2parametersgenerator;
import org.ripple.bouncycastle.crypto.params.desparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

public interface pbe
{
    //
    // pbe based encryption constants - by default we do pkcs12 with sha-1
    //
    static final int        md5          = 0;
    static final int        sha1         = 1;
    static final int        ripemd160    = 2;
    static final int        tiger        = 3;
    static final int        sha256       = 4;
    static final int        md2          = 5;
    static final int        gost3411     = 6;

    static final int        pkcs5s1      = 0;
    static final int        pkcs5s2      = 1;
    static final int        pkcs12       = 2;
    static final int        openssl      = 3;
    static final int        pkcs5s1_utf8 = 4;
    static final int        pkcs5s2_utf8 = 5;

    /**
     * uses the appropriate mixer to generate the key and iv if necessary.
     */
    static class util
    {
        static private pbeparametersgenerator makepbegenerator(
            int                     type,
            int                     hash)
        {
            pbeparametersgenerator  generator;
    
            if (type == pkcs5s1 || type == pkcs5s1_utf8)
            {
                switch (hash)
                {
                case md2:
                    generator = new pkcs5s1parametersgenerator(new md2digest());
                    break;
                case md5:
                    generator = new pkcs5s1parametersgenerator(new md5digest());
                    break;
                case sha1:
                    generator = new pkcs5s1parametersgenerator(new sha1digest());
                    break;
                default:
                    throw new illegalstateexception("pkcs5 scheme 1 only supports md2, md5 and sha1.");
                }
            }
            else if (type == pkcs5s2 || type == pkcs5s2_utf8)
            {
                generator = new pkcs5s2parametersgenerator();
            }
            else if (type == pkcs12)
            {
                switch (hash)
                {
                case md2:
                    generator = new pkcs12parametersgenerator(new md2digest());
                    break;
                case md5:
                    generator = new pkcs12parametersgenerator(new md5digest());
                    break;
                case sha1:
                    generator = new pkcs12parametersgenerator(new sha1digest());
                    break;
                case ripemd160:
                    generator = new pkcs12parametersgenerator(new ripemd160digest());
                    break;
                case tiger:
                    generator = new pkcs12parametersgenerator(new tigerdigest());
                    break;
                case sha256:
                    generator = new pkcs12parametersgenerator(new sha256digest());
                    break;
                case gost3411:
                    generator = new pkcs12parametersgenerator(new gost3411digest());
                    break;
                default:
                    throw new illegalstateexception("unknown digest scheme for pbe encryption.");
                }
            }
            else
            {
                generator = new opensslpbeparametersgenerator();
            }
    
            return generator;
        }

        /**
         * construct a key and iv (if necessary) suitable for use with a 
         * cipher.
         */
        public static cipherparameters makepbeparameters(
            bcpbekey pbekey,
            algorithmparameterspec spec,
            string targetalgorithm)
        {
            if ((spec == null) || !(spec instanceof pbeparameterspec))
            {
                throw new illegalargumentexception("need a pbeparameter spec with a pbe key.");
            }
    
            pbeparameterspec        pbeparam = (pbeparameterspec)spec;
            pbeparametersgenerator  generator = makepbegenerator(pbekey.gettype(), pbekey.getdigest());
            byte[]                  key = pbekey.getencoded();
            cipherparameters        param;
    
            if (pbekey.shouldtrywrongpkcs12())
            {
                key = new byte[2];
            }
            
            generator.init(key, pbeparam.getsalt(), pbeparam.getiterationcount());

            if (pbekey.getivsize() != 0)
            {
                param = generator.generatederivedparameters(pbekey.getkeysize(), pbekey.getivsize());
            }
            else
            {
                param = generator.generatederivedparameters(pbekey.getkeysize());
            }

            if (targetalgorithm.startswith("des"))
            {
                if (param instanceof parameterswithiv)
                {
                    keyparameter    kparam = (keyparameter)((parameterswithiv)param).getparameters();

                    desparameters.setoddparity(kparam.getkey());
                }
                else
                {
                    keyparameter    kparam = (keyparameter)param;

                    desparameters.setoddparity(kparam.getkey());
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
        public static cipherparameters makepbemacparameters(
            bcpbekey pbekey,
            algorithmparameterspec spec)
        {
            if ((spec == null) || !(spec instanceof pbeparameterspec))
            {
                throw new illegalargumentexception("need a pbeparameter spec with a pbe key.");
            }
    
            pbeparameterspec        pbeparam = (pbeparameterspec)spec;
            pbeparametersgenerator  generator = makepbegenerator(pbekey.gettype(), pbekey.getdigest());
            byte[]                  key = pbekey.getencoded();
            cipherparameters        param;
    
            if (pbekey.shouldtrywrongpkcs12())
            {
                key = new byte[2];
            }
            
            generator.init(key, pbeparam.getsalt(), pbeparam.getiterationcount());

            param = generator.generatederivedmacparameters(pbekey.getkeysize());
    
            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }

            return param;
        }
    
        /**
         * construct a key and iv (if necessary) suitable for use with a 
         * cipher.
         */
        public static cipherparameters makepbeparameters(
            pbekeyspec keyspec,
            int type,
            int hash,
            int keysize,
            int ivsize)
        {    
            pbeparametersgenerator  generator = makepbegenerator(type, hash);
            byte[]                  key;
            cipherparameters        param;

            key = convertpassword(type, keyspec);

            generator.init(key, keyspec.getsalt(), keyspec.getiterationcount());
    
            if (ivsize != 0)
            {
                param = generator.generatederivedparameters(keysize, ivsize);
            }
            else
            {
                param = generator.generatederivedparameters(keysize);
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
        public static cipherparameters makepbemacparameters(
            pbekeyspec keyspec,
            int type,
            int hash,
            int keysize)
        {
            pbeparametersgenerator  generator = makepbegenerator(type, hash);
            byte[]                  key;
            cipherparameters        param;
    
            key = convertpassword(type, keyspec);
            
            generator.init(key, keyspec.getsalt(), keyspec.getiterationcount());
    
            param = generator.generatederivedmacparameters(keysize);
    
            for (int i = 0; i != key.length; i++)
            {
                key[i] = 0;
            }
    
            return param;
        }

        private static byte[] convertpassword(int type, pbekeyspec keyspec)
        {
            byte[] key;

            if (type == pkcs12)
            {
                key = pbeparametersgenerator.pkcs12passwordtobytes(keyspec.getpassword());
            }
            else if (type == pkcs5s2_utf8 || type == pkcs5s1_utf8)
            {
                key = pbeparametersgenerator.pkcs5passwordtoutf8bytes(keyspec.getpassword());
            }
            else
            {
                key = pbeparametersgenerator.pkcs5passwordtobytes(keyspec.getpassword());
            }
            return key;
        }
    }
}
