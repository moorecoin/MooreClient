package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.grainv1engine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basestreamcipher;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class grainv1
{
    private grainv1()
    {
    }
    
    public static class base
        extends basestreamcipher
    {
        public base()
        {
            super(new grainv1engine(), 8);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("grainv1", 80, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = grainv1.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.grainv1", prefix + "$base");
            provider.addalgorithm("keygenerator.grainv1", prefix + "$keygen");
        }
    }
}
