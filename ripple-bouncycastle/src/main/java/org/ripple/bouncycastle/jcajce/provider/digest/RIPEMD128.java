package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.ripemd128digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class ripemd128
{
    private ripemd128()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new ripemd128digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new ripemd128digest((ripemd128digest)digest);

            return d;
        }
    }

    /**
     * ripemd128 hashmac
     */
    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new ripemd128digest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacripemd128", 128, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = ripemd128.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.ripemd128", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest." + teletrustobjectidentifiers.ripemd128, "ripemd128");            

            addhmacalgorithm(provider, "ripemd128", prefix + "$hashmac", prefix + "$keygenerator");
        }
    }
}
