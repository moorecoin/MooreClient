package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.asn1.ua.uaobjectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.dstu.keyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

public class dstu4145 
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".dstu.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }
        
        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keyfactory.dstu4145", prefix + "keyfactoryspi");
            provider.addalgorithm("alg.alias.keyfactory.dstu-4145-2002", "dstu4145");
            provider.addalgorithm("alg.alias.keyfactory.dstu4145-3410", "dstu4145");

            registeroid(provider, uaobjectidentifiers.dstu4145le, "dstu4145", new keyfactoryspi());
            registeroidalgorithmparameters(provider, uaobjectidentifiers.dstu4145le, "dstu4145");
            registeroid(provider, uaobjectidentifiers.dstu4145be, "dstu4145", new keyfactoryspi());
            registeroidalgorithmparameters(provider, uaobjectidentifiers.dstu4145be, "dstu4145");

            provider.addalgorithm("keypairgenerator.dstu4145", prefix + "keypairgeneratorspi");
            provider.addalgorithm("alg.alias.keypairgenerator.dstu-4145", "dstu4145");
            provider.addalgorithm("alg.alias.keypairgenerator.dstu-4145-2002", "dstu4145");

            provider.addalgorithm("signature.dstu4145", prefix + "signaturespi");
            provider.addalgorithm("alg.alias.signature.dstu-4145", "dstu4145");
            provider.addalgorithm("alg.alias.signature.dstu-4145-2002", "dstu4145");

            addsignaturealgorithm(provider, "gost3411", "dstu4145le", prefix + "signaturespile", uaobjectidentifiers.dstu4145le);
            addsignaturealgorithm(provider, "gost3411", "dstu4145", prefix + "signaturespi", uaobjectidentifiers.dstu4145be);
        }
    }
}
