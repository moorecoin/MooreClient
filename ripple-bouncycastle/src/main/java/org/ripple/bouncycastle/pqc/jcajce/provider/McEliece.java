package org.ripple.bouncycastle.pqc.jcajce.provider;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetricalgorithmprovider;
import org.ripple.bouncycastle.pqc.asn1.pqcobjectidentifiers;

public class mceliece
{
    private static final string prefix = "org.bouncycastle.pqc.jcajce.provider" + ".mceliece.";

    public static class mappings
        extends asymmetricalgorithmprovider
    {
        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            // mceliecekobaraimai
            provider.addalgorithm("keypairgenerator.mceliecekobaraimai", prefix + "mceliecekeypairgeneratorspi$mceliececca2");
            // mceliecepointcheval
            provider.addalgorithm("keypairgenerator.mceliecepointcheval", prefix + "mceliecekeypairgeneratorspi$mceliececca2");
            // mceliecefujisaki
            provider.addalgorithm("keypairgenerator.mceliecefujisaki", prefix + "mceliecekeypairgeneratorspi$mceliececca2");
            // mceliecepkcs
            provider.addalgorithm("keypairgenerator.mceliecepkcs", prefix + "mceliecekeypairgeneratorspi$mceliece");

            provider.addalgorithm("keypairgenerator." + pqcobjectidentifiers.mceliece, prefix + "mceliecekeypairgeneratorspi$mceliece");
            provider.addalgorithm("keypairgenerator." + pqcobjectidentifiers.mceliececca2, prefix + "mceliecekeypairgeneratorspi$mceliececca2");

            provider.addalgorithm("cipher.mceliecepointcheval", prefix + "mceliecepointchevalcipherspi$mceliecepointcheval");
            provider.addalgorithm("cipher.mceliecepointchevalwithsha1", prefix + "mceliecepointchevalcipherspi$mceliecepointcheval");
            provider.addalgorithm("cipher.mceliecepointchevalwithsha224", prefix + "mceliecepointchevalcipherspi$mceliecepointcheval224");
            provider.addalgorithm("cipher.mceliecepointchevalwithsha256", prefix + "mceliecepointchevalcipherspi$mceliecepointcheval256");
            provider.addalgorithm("cipher.mceliecepointchevalwithsha384", prefix + "mceliecepointchevalcipherspi$mceliecepointcheval384");
            provider.addalgorithm("cipher.mceliecepointchevalwithsha512", prefix + "mceliecepointchevalcipherspi$mceliecepointcheval512");

            provider.addalgorithm("cipher.mceliecepkcs", prefix + "mceliecepkcscipherspi$mceliecepkcs");
            provider.addalgorithm("cipher.mceliecepkcswithsha1", prefix + "mceliecepkcscipherspi$mceliecepkcs");
            provider.addalgorithm("cipher.mceliecepkcswithsha224", prefix + "mceliecepkcscipherspi$mceliecepkcs224");
            provider.addalgorithm("cipher.mceliecepkcswithsha256", prefix + "mceliecepkcscipherspi$mceliecepkcs256");
            provider.addalgorithm("cipher.mceliecepkcswithsha384", prefix + "mceliecepkcscipherspi$mceliecepkcs384");
            provider.addalgorithm("cipher.mceliecepkcswithsha512", prefix + "mceliecepkcscipherspi$mceliecepkcs512");

            provider.addalgorithm("cipher.mceliecekobaraimai", prefix + "mceliecekobaraimaicipherspi$mceliecekobaraimai");
            provider.addalgorithm("cipher.mceliecekobaraimaiwithsha1", prefix + "mceliecekobaraimaicipherspi$mceliecekobaraimai");
            provider.addalgorithm("cipher.mceliecekobaraimaiwithsha224", prefix + "mceliecekobaraimaicipherspi$mceliecekobaraimai224");
            provider.addalgorithm("cipher.mceliecekobaraimaiwithsha256", prefix + "mceliecekobaraimaicipherspi$mceliecekobaraimai256");
            provider.addalgorithm("cipher.mceliecekobaraimaiwithsha384", prefix + "mceliecekobaraimaicipherspi$mceliecekobaraimai384");
            provider.addalgorithm("cipher.mceliecekobaraimaiwithsha512", prefix + "mceliecekobaraimaicipherspi$mceliecekobaraimai512");

            provider.addalgorithm("cipher.mceliecefujisaki", prefix + "mceliecefujisakicipherspi$mceliecefujisaki");
            provider.addalgorithm("cipher.mceliecefujisakiwithsha1", prefix + "mceliecefujisakicipherspi$mceliecefujisaki");
            provider.addalgorithm("cipher.mceliecefujisakiwithsha224", prefix + "mceliecefujisakicipherspi$mceliecefujisaki224");
            provider.addalgorithm("cipher.mceliecefujisakiwithsha256", prefix + "mceliecefujisakicipherspi$mceliecefujisaki256");
            provider.addalgorithm("cipher.mceliecefujisakiwithsha384", prefix + "mceliecefujisakicipherspi$mceliecefujisaki384");
            provider.addalgorithm("cipher.mceliecefujisakiwithsha512", prefix + "mceliecefujisakicipherspi$mceliecefujisaki512");

        }
    }
}
