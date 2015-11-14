package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa.dsautil;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa.keyfactoryspi;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;

public class dsa
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".dsa.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }
        
        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("algorithmparameters.dsa", prefix + "algorithmparametersspi");

            provider.addalgorithm("algorithmparametergenerator.dsa", prefix + "algorithmparametergeneratorspi");

            provider.addalgorithm("keypairgenerator.dsa", prefix + "keypairgeneratorspi");
            provider.addalgorithm("keyfactory.dsa", prefix + "keyfactoryspi");

            provider.addalgorithm("signature.dsa", prefix + "dsasigner$stddsa");
            provider.addalgorithm("signature.nonewithdsa", prefix + "dsasigner$nonedsa");

            provider.addalgorithm("alg.alias.signature.rawdsa", "nonewithdsa");

            addsignaturealgorithm(provider, "sha224", "dsa", prefix + "dsasigner$dsa224", nistobjectidentifiers.dsa_with_sha224);
            addsignaturealgorithm(provider, "sha256", "dsa", prefix + "dsasigner$dsa256", nistobjectidentifiers.dsa_with_sha256);
            addsignaturealgorithm(provider, "sha384", "dsa", prefix + "dsasigner$dsa384", nistobjectidentifiers.dsa_with_sha384);
            addsignaturealgorithm(provider, "sha512", "dsa", prefix + "dsasigner$dsa512", nistobjectidentifiers.dsa_with_sha512);

            provider.addalgorithm("alg.alias.signature.sha/dsa", "dsa");
            provider.addalgorithm("alg.alias.signature.sha1withdsa", "dsa");
            provider.addalgorithm("alg.alias.signature.sha1withdsa", "dsa");
            provider.addalgorithm("alg.alias.signature.1.3.14.3.2.26with1.2.840.10040.4.1", "dsa");
            provider.addalgorithm("alg.alias.signature.1.3.14.3.2.26with1.2.840.10040.4.3", "dsa");
            provider.addalgorithm("alg.alias.signature.dsawithsha1", "dsa");
            provider.addalgorithm("alg.alias.signature.dsawithsha1", "dsa");
            provider.addalgorithm("alg.alias.signature.sha1withdsa", "dsa");
            provider.addalgorithm("alg.alias.signature.dsawithsha1", "dsa");

            provider.addalgorithm("alg.alias.signature.1.2.840.10040.4.3", "dsa");

            asymmetrickeyinfoconverter keyfact = new keyfactoryspi();

            for (int i = 0; i != dsautil.dsaoids.length; i++)
            {
                provider.addalgorithm("alg.alias.signature." + dsautil.dsaoids[i], "dsa");

                registeroid(provider, dsautil.dsaoids[i], "dsa", keyfact);
                registeroidalgorithmparameters(provider, dsautil.dsaoids[i], "dsa");
            }
        }
    }
}
