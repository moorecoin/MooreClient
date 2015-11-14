package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class sha224
{
    private sha224()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new sha224digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new sha224digest((sha224digest)digest);

            return d;
        }
    }

    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new sha224digest()));
        }
    }

    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacsha224", 224, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = sha224.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.sha-224", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest.sha224", "sha-224");
            provider.addalgorithm("alg.alias.messagedigest." + nistobjectidentifiers.id_sha224, "sha-224");

            addhmacalgorithm(provider, "sha224", prefix + "$hashmac",  prefix + "$keygenerator");
            addhmacalias(provider, "sha224", pkcsobjectidentifiers.id_hmacwithsha224);

        }
    }
}
