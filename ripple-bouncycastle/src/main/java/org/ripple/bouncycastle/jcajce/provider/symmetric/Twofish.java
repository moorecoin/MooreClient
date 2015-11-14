package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.twofishengine;
import org.ripple.bouncycastle.crypto.macs.gmac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.blockcipherprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;

public final class twofish
{
    private twofish()
    {
    }

    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new blockcipherprovider()
            {
                public blockcipher get()
                {
                    return new twofishengine();
                }
            });
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("twofish", 256, new cipherkeygenerator());
        }
    }

    public static class gmac
        extends basemac
    {
        public gmac()
        {
            super(new gmac(new gcmblockcipher(new twofishengine())));
        }
    }

    /**
     * pbewithshaandtwofish-cbc
     */
    static public class pbewithshakeyfactory
        extends pbesecretkeyfactory
    {
        public pbewithshakeyfactory()
        {
            super("pbewithshaandtwofish-cbc", null, true, pkcs12, sha1, 256, 128);
        }
    }

    /**
     * pbewithshaandtwofish-cbc
     */
    static public class pbewithsha
        extends baseblockcipher
    {
        public pbewithsha()
        {
            super(new cbcblockcipher(new twofishengine()));
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "twofish iv";
        }
    }

    public static class mappings
        extends symmetricalgorithmprovider
    {
        private static final string prefix = twofish.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.twofish", prefix + "$ecb");
            provider.addalgorithm("keygenerator.twofish", prefix + "$keygen");
            provider.addalgorithm("algorithmparameters.twofish", prefix + "$algparams");

            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaandtwofish", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaandtwofish-cbc", "pkcs12pbe");
            provider.addalgorithm("cipher.pbewithshaandtwofish-cbc",  prefix + "$pbewithsha");
            provider.addalgorithm("secretkeyfactory.pbewithshaandtwofish-cbc", prefix + "$pbewithshakeyfactory");

            addgmacalgorithm(provider, "twofish", prefix + "$gmac", prefix + "$keygen");
        }
    }
}
