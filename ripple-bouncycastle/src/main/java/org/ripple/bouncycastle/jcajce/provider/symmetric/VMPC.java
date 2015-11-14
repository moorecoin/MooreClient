package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.vmpcengine;
import org.ripple.bouncycastle.crypto.macs.vmpcmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basestreamcipher;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class vmpc
{
    private vmpc()
    {
    }
    
    public static class base
        extends basestreamcipher
    {
        public base()
        {
            super(new vmpcengine(), 16);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("vmpc", 128, new cipherkeygenerator());
        }
    }

    public static class mac
        extends basemac
    {
        public mac()
        {
            super(new vmpcmac());
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = vmpc.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.vmpc", prefix + "$base");
            provider.addalgorithm("keygenerator.vmpc", prefix + "$keygen");
            provider.addalgorithm("mac.vmpcmac", prefix + "$mac");
            provider.addalgorithm("alg.alias.mac.vmpc", "vmpcmac");
            provider.addalgorithm("alg.alias.mac.vmpc-mac", "vmpcmac");

        }
    }
}
