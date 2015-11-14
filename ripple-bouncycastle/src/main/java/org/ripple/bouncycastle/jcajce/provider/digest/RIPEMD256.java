package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.ripemd256digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class ripemd256
{
    private ripemd256()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new ripemd256digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new ripemd256digest((ripemd256digest)digest);

            return d;
        }
    }

    /**
     * ripemd256 hmac
     */
    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new ripemd256digest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacripemd256", 256, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = ripemd256.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.ripemd256", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest." + teletrustobjectidentifiers.ripemd256, "ripemd256");

            addhmacalgorithm(provider, "ripemd256", prefix + "$hashmac", prefix + "$keygenerator");
        }
    }
}
