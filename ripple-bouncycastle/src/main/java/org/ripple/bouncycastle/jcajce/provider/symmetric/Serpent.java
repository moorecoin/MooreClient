package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.serpentengine;
import org.ripple.bouncycastle.crypto.macs.gmac;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.blockcipherprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;

public final class serpent
{
    private serpent()
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
                    return new serpentengine();
                }
            });
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("serpent", 192, new cipherkeygenerator());
        }
    }

    public static class serpentgmac
        extends basemac
    {
        public serpentgmac()
        {
            super(new gmac(new gcmblockcipher(new serpentengine())));
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "serpent iv";
        }
    }

    public static class mappings
        extends symmetricalgorithmprovider
    {
        private static final string prefix = serpent.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.serpent", prefix + "$ecb");
            provider.addalgorithm("keygenerator.serpent", prefix + "$keygen");
            provider.addalgorithm("algorithmparameters.serpent", prefix + "$algparams");

            addgmacalgorithm(provider, "serpent", prefix + "$serpentgmac", prefix + "$keygen");
        }
    }
}
