package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.iana.ianaobjectidentifiers;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.ripemd160digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;

public class ripemd160
{
    private ripemd160()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new ripemd160digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new ripemd160digest((ripemd160digest)digest);

            return d;
        }
    }

    /**
     * ripemd160 hmac
     */
    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new ripemd160digest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacripemd160", 160, new cipherkeygenerator());
        }
    }


    //
    // pkcs12 states that the same algorithm should be used
    // for the key generation as is used in the hmac, so that
    // is what we do here.
    //

    /**
     * pbewithhmacripemd160
     */
    public static class pbewithhmac
        extends basemac
    {
        public pbewithhmac()
        {
            super(new hmac(new ripemd160digest()), pkcs12, ripemd160, 160);
        }
    }

    /**
     * pbewithhmacripemd160
     */
    public static class pbewithhmackeyfactory
        extends pbesecretkeyfactory
    {
        public pbewithhmackeyfactory()
        {
            super("pbewithhmacripemd160", null, false, pkcs12, ripemd160, 160, 0);
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = ripemd160.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.ripemd160", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest." + teletrustobjectidentifiers.ripemd160, "ripemd160");

            addhmacalgorithm(provider, "ripemd160", prefix + "$hashmac", prefix + "$keygenerator");
            addhmacalias(provider, "ripemd160", ianaobjectidentifiers.hmacripemd160);


            provider.addalgorithm("secretkeyfactory.pbewithhmacripemd160", prefix + "$pbewithhmackeyfactory");
            provider.addalgorithm("mac.pbewithhmacripemd160", prefix + "$pbewithhmac");
        }
    }
}
