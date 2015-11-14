package org.ripple.bouncycastle.jcajce.provider.keystore;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

public class bc
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.keystore" + ".bc.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keystore.bks", prefix + "bckeystorespi$std");
            provider.addalgorithm("keystore.bks-v1", prefix + "bckeystorespi$version1");
            provider.addalgorithm("keystore.bouncycastle", prefix + "bckeystorespi$bouncycastlestore");
            provider.addalgorithm("alg.alias.keystore.uber", "bouncycastle");
            provider.addalgorithm("alg.alias.keystore.bouncycastle", "bouncycastle");
            provider.addalgorithm("alg.alias.keystore.bouncycastle", "bouncycastle");
        }
    }
}
