package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.gost.keyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

public class gost
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".gost.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }
        
        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keypairgenerator.gost3410", prefix + "keypairgeneratorspi");
            provider.addalgorithm("alg.alias.keypairgenerator.gost-3410", "gost3410");
            provider.addalgorithm("alg.alias.keypairgenerator.gost-3410-94", "gost3410");

            provider.addalgorithm("keyfactory.gost3410", prefix + "keyfactoryspi");
            provider.addalgorithm("alg.alias.keyfactory.gost-3410", "gost3410");
            provider.addalgorithm("alg.alias.keyfactory.gost-3410-94", "gost3410");


            provider.addalgorithm("algorithmparameters.gost3410", prefix + "algorithmparametersspi");
            provider.addalgorithm("algorithmparametergenerator.gost3410", prefix + "algorithmparametergeneratorspi");

            registeroid(provider, cryptoproobjectidentifiers.gostr3410_94, "gost3410", new keyfactoryspi());
            registeroidalgorithmparameters(provider, cryptoproobjectidentifiers.gostr3410_94, "gost3410");

            provider.addalgorithm("signature.gost3410", prefix + "signaturespi");
            provider.addalgorithm("alg.alias.signature.gost-3410", "gost3410");
            provider.addalgorithm("alg.alias.signature.gost-3410-94", "gost3410");
            provider.addalgorithm("alg.alias.signature.gost3411withgost3410", "gost3410");
            provider.addalgorithm("alg.alias.signature.gost3411withgost3410", "gost3410");
            provider.addalgorithm("alg.alias.signature.gost3411withgost3410", "gost3410");
            provider.addalgorithm("alg.alias.signature." + cryptoproobjectidentifiers.gostr3411_94_with_gostr3410_94, "gost3410");


            provider.addalgorithm("alg.alias.algorithmparametergenerator.gost-3410", "gost3410");
            provider.addalgorithm("alg.alias.algorithmparameters.gost-3410", "gost3410");
        }
    }
}
