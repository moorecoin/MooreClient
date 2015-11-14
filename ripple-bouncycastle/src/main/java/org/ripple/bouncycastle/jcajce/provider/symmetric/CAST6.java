package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.cast6engine;
import org.ripple.bouncycastle.crypto.macs.gmac;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public final class cast6
{
    private cast6()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new cast6engine());
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("cast6", 256, new cipherkeygenerator());
        }
    }

    public static class gmac
        extends basemac
    {
        public gmac()
        {
            super(new gmac(new gcmblockcipher(new cast6engine())));
        }
    }

    public static class mappings
        extends symmetricalgorithmprovider
    {
        private static final string prefix = cast6.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.cast6", prefix + "$ecb");
            provider.addalgorithm("keygenerator.cast6", prefix + "$keygen");

            addgmacalgorithm(provider, "cast6", prefix + "$gmac", prefix + "$keygen");
        }
    }
}
