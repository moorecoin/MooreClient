package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.salsa20engine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basestreamcipher;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class salsa20
{
    private salsa20()
    {
    }
    
    public static class base
        extends basestreamcipher
    {
        public base()
        {
            super(new salsa20engine(), 8);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("salsa20", 128, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = salsa20.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.salsa20", prefix + "$base");
            provider.addalgorithm("keygenerator.salsa20", prefix + "$keygen");

        }
    }
}
