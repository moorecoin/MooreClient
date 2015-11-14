package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

abstract class digestalgorithmprovider
    extends algorithmprovider
{
    protected void addhmacalgorithm(
        configurableprovider provider,
        string algorithm,
        string algorithmclassname,
        string keygeneratorclassname)
    {
        string mainname = "hmac" + algorithm;

        provider.addalgorithm("mac." + mainname, algorithmclassname);
        provider.addalgorithm("alg.alias.mac.hmac-" + algorithm, mainname);
        provider.addalgorithm("alg.alias.mac.hmac/" + algorithm, mainname);
        provider.addalgorithm("keygenerator." + mainname, keygeneratorclassname);
        provider.addalgorithm("alg.alias.keygenerator.hmac-" + algorithm, mainname);
        provider.addalgorithm("alg.alias.keygenerator.hmac/" + algorithm, mainname);
    }

    protected void addhmacalias(
        configurableprovider provider,
        string algorithm,
        asn1objectidentifier oid)
    {
        string mainname = "hmac" + algorithm;

        provider.addalgorithm("alg.alias.mac." + oid, mainname);
        provider.addalgorithm("alg.alias.keygenerator." + oid, mainname);
    }
}
