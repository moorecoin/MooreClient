package org.ripple.bouncycastle.jcajce.provider.digest;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.digests.sha3digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;

public class sha3
{
    private sha3()
    {

    }

    static public class digestsha3
        extends bcmessagedigest
        implements cloneable
    {
        public digestsha3(int size)
        {
            super(new sha3digest(size));
        }

        public object clone()
            throws clonenotsupportedexception
        {
            bcmessagedigest d = (bcmessagedigest)super.clone();
            d.digest = new sha3digest((sha3digest)digest);

            return d;
        }
    }

    static public class digest224
        extends digestsha3
    {
        public digest224()
        {
            super(224);
        }
    }

    static public class digest256
        extends digestsha3
    {
        public digest256()
        {
            super(256);
        }
    }

    static public class digest384
        extends digestsha3
    {
        public digest384()
        {
            super(384);
        }
    }

    static public class digest512
        extends digestsha3
    {
        public digest512()
        {
            super(512);
        }
    }

    /**
     * sha3 hmac
     */
    public static class hashmac224
        extends basemac
    {
        public hashmac224()
        {
            super(new hmac(new sha3digest(224)));
        }
    }

    public static class hashmac256
        extends basemac
    {
        public hashmac256()
        {
            super(new hmac(new sha3digest(256)));
        }
    }

    public static class hashmac384
        extends basemac
    {
        public hashmac384()
        {
            super(new hmac(new sha3digest(384)));
        }
    }

    public static class hashmac512
        extends basemac
    {
        public hashmac512()
        {
            super(new hmac(new sha3digest(512)));
        }
    }

    public static class keygenerator224
        extends basekeygenerator
    {
        public keygenerator224()
        {
            super("hmacsha3-224", 224, new cipherkeygenerator());
        }
    }

    public static class keygenerator256
        extends basekeygenerator
    {
        public keygenerator256()
        {
            super("hmacsha3-256", 256, new cipherkeygenerator());
        }
    }

    public static class keygenerator384
        extends basekeygenerator
    {
        public keygenerator384()
        {
            super("hmacsha3-384", 384, new cipherkeygenerator());
        }
    }

    public static class keygenerator512
        extends basekeygenerator
    {
        public keygenerator512()
        {
            super("hmacsha3-512", 512, new cipherkeygenerator());
        }
    }

    public static class mappings
        extends digestalgorithmprovider
    {
        private static final string prefix = sha3.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("messagedigest.sha3-224", prefix + "$digest224");
            provider.addalgorithm("messagedigest.sha3-256", prefix + "$digest256");
            provider.addalgorithm("messagedigest.sha3-384", prefix + "$digest384");
            provider.addalgorithm("messagedigest.sha3-512", prefix + "$digest512");
            // look for an object identifier (nist???) for sha3 family
            // provider.addalgorithm("alg.alias.messagedigest." + oiwobjectidentifiers.idsha3, "sha3-224"); // *****

            addhmacalgorithm(provider, "sha3-224", prefix + "$hashmac224", prefix + "$keygenerator224");
            addhmacalgorithm(provider, "sha3-256", prefix + "$hashmac256", prefix + "$keygenerator256");
            addhmacalgorithm(provider, "sha3-384", prefix + "$hashmac384", prefix + "$keygenerator384");
            addhmacalgorithm(provider, "sha3-512", prefix + "$hashmac512", prefix + "$keygenerator512");
        }
    }
}
