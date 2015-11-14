package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.teaengine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class tea
{
    private tea()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new teaengine());
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("tea", 128, new cipherkeygenerator());
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "tea iv";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = tea.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.tea", prefix + "$ecb");
            provider.addalgorithm("keygenerator.tea", prefix + "$keygen");
            provider.addalgorithm("algorithmparameters.tea", prefix + "$algparams");

        }
    }
}
