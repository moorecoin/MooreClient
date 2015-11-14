package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

/**
 * for some reason the class path project thinks that such a keyfactory will exist.
 */
public class x509
{
    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {

        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keyfactory.x.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.keyfactory");
            provider.addalgorithm("alg.alias.keyfactory.x509", "x.509");

            //
            // certificate factories.
            //
            provider.addalgorithm("certificatefactory.x.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.certificatefactory");
            provider.addalgorithm("alg.alias.certificatefactory.x509", "x.509");
        }
    }
}
