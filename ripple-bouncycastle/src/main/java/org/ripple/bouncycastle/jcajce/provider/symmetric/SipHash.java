package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public final class siphash
{
    private siphash()
    {
    }
    
    public static class mac
        extends basemac
    {
        public mac()
        {
            super(new org.ripple.bouncycastle.crypto.macs.siphash());
        }
    }

    public static class mac48
        extends basemac
    {
        public mac48()
        {
            super(new org.ripple.bouncycastle.crypto.macs.siphash(4, 8));
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = siphash.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("mac.siphash", prefix + "$mac");
            provider.addalgorithm("alg.alias.mac.siphash-2-4", "siphash");
            provider.addalgorithm("mac.siphash-4-8", prefix + "$mac48");
        }
    }
}
