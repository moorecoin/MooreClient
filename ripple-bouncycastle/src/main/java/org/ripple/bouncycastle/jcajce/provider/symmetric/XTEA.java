package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.xteaengine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class xtea
{
    private xtea()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new xteaengine());
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("xtea", 128, new cipherkeygenerator());
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "xtea iv";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = xtea.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.xtea", prefix + "$ecb");
            provider.addalgorithm("keygenerator.xtea", prefix + "$keygen");
            provider.addalgorithm("algorithmparameters.xtea", prefix + "$algparams");

        }
    }
}
