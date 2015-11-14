package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.digests.sha512tdigest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.crypto.macs.oldhmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class sha512
{
    private sha512()
    {

    }

    static public class digest
        extends bcmessagedigest
        implements cloneable
    {
        public digest()
        {
            super(new sha512digest());
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digest d = (digest)super.clone();
            d.digest = new sha512digest((sha512digest)digest);

            return d;
        }
    }

    static public class digestt
        extends bcmessagedigest
        implements cloneable
    {
        public digestt(int bitlength)
        {
            super(new sha512tdigest(bitlength));
        }

        public object clone()
            throws clonenotsupportedexception
        {
            digestt d = (digestt)super.clone();
            d.digest = new sha512tdigest((sha512tdigest)digest);

            return d;
        }
    }

    static public class digestt224
        extends digestt
    {
        public digestt224()
        {
            super(224);
        }
    }

    static public class digestt256
        extends digestt
    {
        public digestt256()
        {
            super(256);
        }
    }

    public static class hashmac
        extends basemac
    {
        public hashmac()
        {
            super(new hmac(new sha512digest()));
        }
    }

    public static class hashmact224
        extends basemac
    {
        public hashmact224()
        {
            super(new hmac(new sha512tdigest(224)));
        }
    }

    public static class hashmact256
        extends basemac
    {
        public hashmact256()
        {
            super(new hmac(new sha512tdigest(256)));
        }
    }

    /**
     * sha-512 hmac
     */
    public static class oldsha512
        extends basemac
    {
        public oldsha512()
        {
            super(new oldhmac(new sha512digest()));
        }
    }

    /**
     * hmacsha512
     */
    public static class keygenerator
        extends basekeygenerator
    {
        public keygenerator()
        {
            super("hmacsha512", 512, new cipherkeygenerator());
        }
    }

    public static class keygeneratort224
        extends basekeygenerator
    {
        public keygeneratort224()
        {
            super("hmacsha512/224", 224, new cipherkeygenerator());
        }
    }

    public static class keygeneratort256
        extends basekeygenerator
    {
        public keygeneratort256()
        {
            super("hmacsha512/256", 256, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = sha512.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.sha-512", prefix + "$digest");
            provider.addalgorithm("alg.alias.messagedigest.sha512", "sha-512");
            provider.addalgorithm("alg.alias.messagedigest." + nistobjectidentifiers.id_sha512, "sha-512");

            provider.addalgorithm("messagedigest.sha-512/224", prefix + "$digestt224");
            provider.addalgorithm("alg.alias.messagedigest.sha512/224", "sha-512/224");
            provider.addalgorithm("alg.alias.messagedigest." + nistobjectidentifiers.id_sha512_224, "sha-512/224");

            provider.addalgorithm("messagedigest.sha-512/256", prefix + "$digestt256");
            provider.addalgorithm("alg.alias.messagedigest.sha512256", "sha-512/256");
            provider.addalgorithm("alg.alias.messagedigest." + nistobjectidentifiers.id_sha512_256, "sha-512/256");

            provider.addalgorithm("mac.oldhmacsha512", prefix + "$oldsha512");

            addhmacalgorithm(provider, "sha512", prefix + "$hashmac",  prefix + "$keygenerator");
            addhmacalias(provider, "sha512", pkcsobjectidentifiers.id_hmacwithsha512);

            addhmacalgorithm(provider, "sha512/224", prefix + "$hashmact224",  prefix + "$keygeneratort224");
            addhmacalgorithm(provider, "sha512/256", prefix + "$hashmact256",  prefix + "$keygeneratort256");
        }
    }

}
