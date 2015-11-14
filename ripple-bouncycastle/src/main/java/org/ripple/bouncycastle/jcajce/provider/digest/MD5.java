package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.iana.ianaobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class md5
{
    private md5()
    {

    }

    /**
     * md5 hashmac
     */
    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new md5digest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacmd5", 128, new cipherkeygenerator());
        }
    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new md5digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new md5digest((md5digest)digest);

            return d;
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = md5.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.md5", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest." + pkcsobjectidentifiers.md5, "md5");

            addhmacalgorithm(provider, "md5", prefix + "$hashmac", prefix + "$keygenerator");
            addhmacalias(provider, "md5", ianaobjectidentifiers.hmacmd5);
        }
    }
}
