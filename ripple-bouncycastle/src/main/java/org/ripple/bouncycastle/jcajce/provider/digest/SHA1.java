package org.ripple.bouncycastle.jcajce.provider.digest;

import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;

import javax.crypto.secretkey;
import javax.crypto.spec.pbekeyspec;

import org.ripple.bouncycastle.asn1.iana.ianaobjectidentifiers;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.bcpbekey;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basesecretkeyfactory;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbe;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;

public class sha1
{
    private sha1()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new sha1digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new sha1digest((sha1digest)digest);

            return d;
        }
    }

    /**
     * sha1 hmac
     */
    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new sha1digest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacsha1", 160, new cipherkeygenerator());
        }
    }

    /**
     * sha1 hmac
     */
    public static class sha1mac
        extends basemac
    {
        public sha1mac()
        {
            super(new hmac(new sha1digest()));
        }
    }

    /**
     * pbewithhmacsha
     */
    public static class pbewithmackeyfactory
        extends pbesecretkeyfactory
    {
        public pbewithmackeyfactory()
        {
            super("pbewithhmacsha", null, false, pkcs12, sha1, 160, 0);
        }
    }


    public static class basepbkdf2withhmacsha1
        extends basesecretkeyfactory
    {
        private int scheme;

        public basepbkdf2withhmacsha1(string name, int scheme)
        {
            super(name, pkcsobjectidentifiers.id_pbkdf2);

            this.scheme = scheme;
        }

        protected secretkey enginegeneratesecret(
            keyspec keyspec)
            throws invalidkeyspecexception
        {
            if (keyspec instanceof pbekeyspec)
            {
                pbekeyspec pbespec = (pbekeyspec)keyspec;

                if (pbespec.getsalt() == null)
                {
                    throw new invalidkeyspecexception("missing required salt");
                }

                if (pbespec.getiterationcount() <= 0)
                {
                    throw new invalidkeyspecexception("positive iteration count required: "
                        + pbespec.getiterationcount());
                }

                if (pbespec.getkeylength() <= 0)
                {
                    throw new invalidkeyspecexception("positive key length required: "
                        + pbespec.getkeylength());
                }

                if (pbespec.getpassword().length == 0)
                {
                    throw new illegalargumentexception("password empty");
                }

                int digest = sha1;
                int keysize = pbespec.getkeylength();
                int ivsize = -1;    // jdk 1,2 and earlier does not understand simplified version.
                cipherparameters param = pbe.util.makepbemacparameters(pbespec, scheme, digest, keysize);

                return new bcpbekey(this.algname, this.algoid, scheme, digest, keysize, ivsize, pbespec, param);
            }

            throw new invalidkeyspecexception("invalid keyspec");
        }
    }

    public static class pbkdf2withhmacsha1utf8
        extends basepbkdf2withhmacsha1
    {
        public pbkdf2withhmacsha1utf8()
        {
            super("pbkdf2withhmacsha1", pkcs5s2_utf8);
        }
    }

    public static class pbkdf2withhmacsha18bit
        extends basepbkdf2withhmacsha1
    {
        public pbkdf2withhmacsha18bit()
        {
            super("pbkdf2withhmacsha1and8bit", pkcs5s2);
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = sha1.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.sha-1", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest.sha1", "sha-1");
            provider.addalgorithm("alg.alias.messagedigest.sha", "sha-1");
            provider.addalgorithm("alg.alias.messagedigest." + oiwobjectidentifiers.idsha1, "sha-1");

            addhmacalgorithm(provider, "sha1", prefix + "$hashmac", prefix + "$keygenerator");
            addhmacalias(provider, "sha1", pkcsobjectidentifiers.id_hmacwithsha1);
            addhmacalias(provider, "sha1", ianaobjectidentifiers.hmacsha1);

            provider.addalgorithm("mac.pbewithhmacsha", prefix + "$sha1mac");
            provider.addalgorithm("mac.pbewithhmacsha1", prefix + "$sha1mac");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithhmacsha", "pbewithhmacsha1");
            provider.addalgorithm("alg.alias.secretkeyfactory." + oiwobjectidentifiers.idsha1, "pbewithhmacsha1");
            provider.addalgorithm("alg.alias.mac." + oiwobjectidentifiers.idsha1, "pbewithhmacsha");

            provider.addalgorithm("secretkeyfactory.pbewithhmacsha1", prefix + "$pbewithmackeyfactory");
            provider.addalgorithm("secretkeyfactory.pbkdf2withhmacsha1", prefix + "$pbkdf2withhmacsha1utf8");
            provider.addalgorithm("alg.alias.secretkeyfactory." + pkcsobjectidentifiers.id_pbkdf2, "pbkdf2withhmacsha1");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbkdf2withhmacsha1andutf8", "pbkdf2withhmacsha1");
            provider.addalgorithm("secretkeyfactory.pbkdf2withhmacsha1and8bit", prefix + "$pbkdf2withhmacsha18bit");
        }
    }
}
