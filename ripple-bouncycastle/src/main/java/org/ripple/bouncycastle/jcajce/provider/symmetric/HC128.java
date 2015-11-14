package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.hc128engine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basestreamcipher;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class hc128
{
    private hc128()
    {
    }
    
    public static class base
        extends basestreamcipher
    {
        public base()
        {
            super(new hc128engine(), 16);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("hc128", 128, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = hc128.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.hc128", prefix + "$base");
            provider.addalgorithm("keygenerator.hc128", prefix + "$keygen");
        }
    }
}
