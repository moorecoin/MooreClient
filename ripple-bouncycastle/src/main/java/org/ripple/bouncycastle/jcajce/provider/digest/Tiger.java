package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.iana.ianaobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.tigerdigest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;

public class tiger
{
    private tiger()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new tigerdigest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new tigerdigest((tigerdigest)digest);

            return d;
        }
    }

    /**
     * tiger hmac
     */
    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new tigerdigest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmactiger", 192, new cipherkeygenerator());
        }
    }

    /**
     * tiger hmac
     */
    public static class tigerhmac
        extends basemac
    {
        public tigerhmac()
        {
            super(new hmac(new tigerdigest()));
        }
    }

    /**
     * pbewithhmactiger
     */
    public static class pbewithmackeyfactory
        extends pbesecretkeyfactory
    {
        public pbewithmackeyfactory()
        {
            super("pbewithhmactiger", null, false, pkcs12, tiger, 192, 0);
        }
    }

    /**
     * pbewithhmactiger
     */
    public static class pbewithhashmac
        extends basemac
    {
        public pbewithhashmac()
        {
            super(new hmac(new tigerdigest()), pkcs12, tiger, 192);
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = tiger.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.tiger", prefix + "$digest");
            provider.addalgorithm("messagedigest.tiger", prefix + "$digest"); // jdk 1.1.

            addhmacalgorithm(provider, "tiger", prefix + "$hashmac", prefix + "$keygenerator");
            addhmacalias(provider, "tiger", ianaobjectidentifiers.hmactiger);

            provider.addalgorithm("secretkeyfactory.pbewithhmactiger", prefix + "$pbewithmackeyfactory");
        }
    }
}
