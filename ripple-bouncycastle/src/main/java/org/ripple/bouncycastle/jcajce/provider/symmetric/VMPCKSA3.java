package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.vmpcksa3engine;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basestreamcipher;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class vmpcksa3
{
    private vmpcksa3()
    {
    }
    
    public static class base
        extends basestreamcipher
    {
        public base()
        {
            super(new vmpcksa3engine(), 16);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("vmpc-ksa3", 128, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = vmpcksa3.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.vmpc-ksa3", prefix + "$base");
            provider.addalgorithm("keygenerator.vmpc-ksa3", prefix + "$keygen");

        }
    }
}
