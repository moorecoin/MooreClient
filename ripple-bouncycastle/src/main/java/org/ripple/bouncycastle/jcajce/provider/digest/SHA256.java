package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;

public class sha256
{
    private sha256()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new sha256digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new sha256digest((sha256digest)digest);

            return d;
        }
    }

    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new sha256digest()));
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
            super("pbewithhmacsha256", null, false, pkcs12, sha256, 256, 0);
        }
    }

    /**
     * hmacsha256
     */
    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacsha256", 256, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = sha256.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.sha-256", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest.sha256", "sha-256");
            provider.addalgorithm("alg.alias.messagedigest." + nistobjectidentifiers.id_sha256, "sha-256");

            provider.addalgorithm("secretkeyfactory.pbewithhmacsha256", prefix + "$pbewithmackeyfactory");
            provider.addalgorithm("alg.alias.secretkeyfactory.pbewithhmacsha-256", "pbewithhmacsha256");
            provider.addalgorithm("alg.alias.secretkeyfactory." + nistobjectidentifiers.id_sha256, "pbewithhmacsha256");

            addhmacalgorithm(provider, "sha256", prefix + "$hashmac",  prefix + "$keygenerator");
            addhmacalias(provider, "sha256", pkcsobjectidentifiers.id_hmacwithsha256);
            addhmacalias(provider, "sha256", nistobjectidentifiers.id_sha256);
        }
    }
}
