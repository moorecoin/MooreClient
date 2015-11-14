package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.grain128engine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basestreamcipher;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class grain128
{
    private grain128()
    {
    }
    
    public static class base
        extends basestreamcipher
    {
        public base()
        {
            super(new grain128engine(), 12);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("grain128", 128, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = grain128.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.grain128", prefix + "$base");
            provider.addalgorithm("keygenerator.grain128", prefix + "$keygen");
        }
    }
}
