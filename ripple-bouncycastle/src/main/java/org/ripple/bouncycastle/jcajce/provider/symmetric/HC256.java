package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.hc256engine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basestreamcipher;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class hc256
{
    private hc256()
    {
    }
    
    public static class base
        extends basestreamcipher
    {
        public base()
        {
            super(new hc256engine(), 32);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("hc256", 256, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = hc256.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.hc256", prefix + "$base");
            provider.addalgorithm("keygenerator.hc256", prefix + "$keygen");
        }
    }
}
