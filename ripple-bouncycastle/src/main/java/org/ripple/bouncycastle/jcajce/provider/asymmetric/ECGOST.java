package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.ecgost.keyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

public class ecgost
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".ecgost.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }
        
        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keyfactory.ecgost3410", prefix + "keyfactoryspi");
            provider.addalgorithm("alg.alias.keyfactory.gost-3410-2001", "ecgost3410");
            provider.addalgorithm("alg.alias.keyfactory.ecgost-3410", "ecgost3410");

            registeroid(provider, cryptoproobjectidentifiers.gostr3410_2001, "ecgost3410", new keyfactoryspi());
            registeroidalgorithmparameters(provider, cryptoproobjectidentifiers.gostr3410_2001, "ecgost3410");

            provider.addalgorithm("keypairgenerator.ecgost3410", prefix + "keypairgeneratorspi");
            provider.addalgorithm("alg.alias.keypairgenerator.ecgost-3410", "ecgost3410");
            provider.addalgorithm("alg.alias.keypairgenerator.gost-3410-2001", "ecgost3410");

            provider.addalgorithm("signature.ecgost3410", prefix + "signaturespi");
            provider.addalgorithm("alg.alias.signature.ecgost-3410", "ecgost3410");
            provider.addalgorithm("alg.alias.signature.gost-3410-2001", "ecgost3410");

            addsignaturealgorithm(provider, "gost3411", "ecgost3410", prefix + "signaturespi", cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_2001);
        }
    }
}
