package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.md4digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class md4
{
    private md4()
    {

    }

    /**
     * md4 hashmac
     */
    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new md4digest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacmd4", 128, new cipherkeygenerator());
        }
    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new md4digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new md4digest((md4digest)digest);

            return d;
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = md4.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.md4", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest." + pkcsobjectidentifiers.md4, "md4");

            addhmacalgorithm(provider, "md4", prefix + "$hashmac", prefix + "$keygenerator");
        }
    }
}
