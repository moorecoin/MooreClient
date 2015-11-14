package org.ripple.bouncycastle.jcajce.provider.symmetric;

import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

abstract class symmetricalgorithmprovider
    extends algorithmprovider
{
    protected void addgmacalgorithm(
        configurableprovider provider,
        string algorithm,
        string algorithmclassname,
        string keygeneratorclassname)
    {
        provider.addalgorithm("mac." + algorithm + "-gmac", algorithmclassname);
        provider.addalgorithm("alg.alias.mac." + algorithm + "gmac", algorithm + "-gmac");

        provider.addalgorithm("keygenerator." + algorithm + "-gmac", keygeneratorclassname);
        provider.addalgorithm("alg.alias.keygenerator." + algorithm + "gmac",  algorithm + "-gmac");
    }
}
