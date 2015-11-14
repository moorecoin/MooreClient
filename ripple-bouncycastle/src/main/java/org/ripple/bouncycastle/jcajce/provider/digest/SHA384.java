package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.crypto.macs.oldhmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class sha384
{
    private sha384()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new sha384digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new sha384digest((sha384digest)digest);

            return d;
        }
    }

    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new sha384digest()));
        }
    }

    /**
     * hmacsha384
     */
    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacsha384", 384, new cipherkeygenerator());
        }
    }

    public static class oldsha384
        extends basemac
    {
        public oldsha384()
        {
            super(new oldhmac(new sha384digest()));
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = sha384.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.sha-384", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest.sha384", "sha-384");
            provider.addalgorithm("alg.alias.messagedigest." + nistobjectidentifiers.id_sha384, "sha-384");
            provider.addalgorithm("mac.oldhmacsha384", prefix + "$oldsha384");

            addhmacalgorithm(provider, "sha384", prefix + "$hashmac",  prefix + "$keygenerator");
            addhmacalias(provider, "sha384", pkcsobjectidentifiers.id_hmacwithsha384);
        }
    }
}
