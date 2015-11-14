package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.elgamal.keyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;

public class elgamal
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".elgamal.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }
        
        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("algorithmparametergenerator.elgamal", prefix + "algorithmparametergeneratorspi");
            provider.addalgorithm("algorithmparametergenerator.elgamal", prefix + "algorithmparametergeneratorspi");
            provider.addalgorithm("algorithmparameters.elgamal", prefix + "algorithmparametersspi");
            provider.addalgorithm("algorithmparameters.elgamal", prefix + "algorithmparametersspi");

            provider.addalgorithm("cipher.elgamal", prefix + "cipherspi$nopadding");
            provider.addalgorithm("cipher.elgamal", prefix + "cipherspi$nopadding");
            provider.addalgorithm("alg.alias.cipher.elgamal/ecb/pkcs1padding", "elgamal/pkcs1");
            provider.addalgorithm("alg.alias.cipher.elgamal/none/pkcs1padding", "elgamal/pkcs1");
            provider.addalgorithm("alg.alias.cipher.elgamal/none/nopadding", "elgamal");

            provider.addalgorithm("cipher.elgamal/pkcs1", prefix + "cipherspi$pkcs1v1_5padding");
            provider.addalgorithm("keyfactory.elgamal", prefix + "keyfactoryspi");
            provider.addalgorithm("keyfactory.elgamal", prefix + "keyfactoryspi");

            provider.addalgorithm("keypairgenerator.elgamal", prefix + "keypairgeneratorspi");
            provider.addalgorithm("keypairgenerator.elgamal", prefix + "keypairgeneratorspi");

            asymmetrickeyinfoconverter keyfact = new keyfactoryspi();

            registeroid(provider, oiwobjectidentifiers.elgamalalgorithm, "elgamal", keyfact);
            registeroidalgorithmparameters(provider, oiwobjectidentifiers.elgamalalgorithm, "elgamal");
        }
    }
}
