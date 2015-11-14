package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

public class ies
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".ies.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("algorithmparameters.ies", prefix + "algorithmparametersspi");
            provider.addalgorithm("cipher.ies", prefix + "cipherspi$ies");
        }
    }
}
