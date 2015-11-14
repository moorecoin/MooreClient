package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.gost3411digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class gost3411
{
    private gost3411()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new gost3411digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new gost3411digest((gost3411digest)digest);

            return d;
        }
    }

    /**
     * gost3411 hmac
     */
    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new gost3411digest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacgost3411", 256, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = gost3411.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.gost3411", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest.gost", "gost3411");
            provider.addalgorithm("alg.alias.messagedigest.gost-3411", "gost3411");
            provider.addalgorithm("alg.alias.messagedigest." + cryptoproobjectidentifiers.gostr3411, "gost3411");

            addhmacalgorithm(provider, "gost3411", prefix + "$hashmac", prefix + "$keygenerator");
            addhmacalias(provider, "gost3411", cryptoproobjectidentifiers.gostr3411);
        }
    }
}
