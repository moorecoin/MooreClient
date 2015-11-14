package org.ripple.bouncycastle.pqc.jcajce.provider;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;
import org.ripple.bouncycastle.pqc.asn1.pqcobjectidentifiers;
import org.ripple.bouncycastle.pqc.jcajce.provider.rainbow.rainbowkeyfactoryspi;

public class rainbow
{
    private static final string prefix = "org.bouncycastle.pqc.jcajce.provider" + ".rainbow.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keyfactory.rainbow", prefix + "rainbowkeyfactoryspi");
            provider.addalgorithm("keypairgenerator.rainbow", prefix + "rainbowkeypairgeneratorspi");

            addsignaturealgorithm(provider, "sha224", "rainbow", prefix + "signaturespi$withsha224", pqcobjectidentifiers.rainbowwithsha224);
            addsignaturealgorithm(provider, "sha256", "rainbow", prefix + "signaturespi$withsha256", pqcobjectidentifiers.rainbowwithsha256);
            addsignaturealgorithm(provider, "sha384", "rainbow", prefix + "signaturespi$withsha384", pqcobjectidentifiers.rainbowwithsha384);
            addsignaturealgorithm(provider, "sha512", "rainbow", prefix + "signaturespi$withsha512", pqcobjectidentifiers.rainbowwithsha512);

            asymmetrickeyinfoconverter keyfact = new rainbowkeyfactoryspi();

            registeroid(provider, pqcobjectidentifiers.rainbow, "rainbow", keyfact);
            registeroidalgorithmparameters(provider, pqcobjectidentifiers.rainbow, "rainbow");
        }
    }
}
