package org.ripple.bouncycastle.jcajce.provider.util;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;

public abstract class asymmetricalgorithmprovider
    extends algorithmprovider
{       
    protected void addsignaturealgorithm(
        configurableprovider provider,
        string digest,
        string algorithm,
        string classname,
        asn1objectidentifier oid)
    {
        string mainname = digest + "with" + algorithm;
        string jdk11variation1 = digest + "with" + algorithm;
        string jdk11variation2 = digest + "with" + algorithm;
        string alias = digest + "/" + algorithm;

        provider.addalgorithm("signature." + mainname, classname);
        provider.addalgorithm("alg.alias.signature." + jdk11variation1, mainname);
        provider.addalgorithm("alg.alias.signature." + jdk11variation2, mainname);
        provider.addalgorithm("alg.alias.signature." + alias, mainname);
        provider.addalgorithm("alg.alias.signature." + oid, mainname);
        provider.addalgorithm("alg.alias.signature.oid." + oid, mainname);
    }

    protected void registeroid(configurableprovider provider, asn1objectidentifier oid, string name, asymmetrickeyinfoconverter keyfactory)
    {
        provider.addalgorithm("alg.alias.keyfactory." + oid, name);
        provider.addalgorithm("alg.alias.keypairgenerator." + oid, name);

        provider.addkeyinfoconverter(oid, keyfactory);
    }

    protected void registeroidalgorithmparameters(configurableprovider provider, asn1objectidentifier oid, string name)
    {
        provider.addalgorithm("alg.alias.algorithmparametergenerator." + oid, name);
        provider.addalgorithm("alg.alias.algorithmparameters." + oid, name);
    }
}
