package org.ripple.bouncycastle.jcajce.provider.asymmetric;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;

public class dh
{
    private static final string prefix = "org.bouncycastle.jcajce.provider.asymmetric" + ".dh.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("keypairgenerator.dh", prefix + "keypairgeneratorspi");
            provider.addalgorithm("alg.alias.keypairgenerator.diffiehellman", "dh");

            provider.addalgorithm("keyagreement.dh", prefix + "keyagreementspi");
            provider.addalgorithm("alg.alias.keyagreement.diffiehellman", "dh");

            provider.addalgorithm("keyfactory.dh", prefix + "keyfactoryspi");
            provider.addalgorithm("alg.alias.keyfactory.diffiehellman", "dh");

            provider.addalgorithm("algorithmparameters.dh", prefix + "algorithmparametersspi");
            provider.addalgorithm("alg.alias.algorithmparameters.diffiehellman", "dh");

            provider.addalgorithm("alg.alias.algorithmparametergenerator.diffiehellman", "dh");

            provider.addalgorithm("algorithmparametergenerator.dh", prefix + "algorithmparametergeneratorspi");
            
            provider.addalgorithm("cipher.dhies", prefix + "iescipher$ies");
            provider.addalgorithm("cipher.dhieswithaes", prefix + "iescipher$ieswithaes");
            provider.addalgorithm("cipher.dhieswithaes", prefix + "iescipher$ieswithaes");
            provider.addalgorithm("cipher.dhieswithdesede", prefix + "iescipher$ieswithdesede");
        }
    }
}
