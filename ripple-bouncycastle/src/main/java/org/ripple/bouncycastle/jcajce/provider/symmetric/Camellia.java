package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.asn1.ntt.nttobjectidentifiers;
import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.camelliaengine;
import org.ripple.bouncycastle.crypto.engines.camelliawrapengine;
import org.ripple.bouncycastle.crypto.engines.rfc3211wrapengine;
import org.ripple.bouncycastle.crypto.macs.gmac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basewrapcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.blockcipherprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class camellia
{
    private camellia()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new blockcipherprovider()
            {
                public blockcipher get()
                {
                    return new camelliaengine();
                }
            });
        }
    }

    public static class cbc
       extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new camelliaengine()), 128);
        }
    }

    public static class wrap
        extends basewrapcipher
    {
        public wrap()
        {
            super(new camelliawrapengine());
        }
    }

    public static class rfc3211wrap
        extends basewrapcipher
    {
        public rfc3211wrap()
        {
            super(new rfc3211wrapengine(new camelliaengine()), 16);
        }
    }

    public static class gmac
        extends basemac
    {
        public gmac()
        {
            super(new gmac(new gcmblockcipher(new camelliaengine())));
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            this(256);
        }

        public keygen(int keysize)
        {
            super("camellia", keysize, new cipherkeygenerator());
        }
    }

    public static class keygen128
        extends keygen
    {
        public keygen128()
        {
            super(128);
        }
    }

    public static class keygen192
        extends keygen
    {
        public keygen192()
        {
            super(192);
        }
    }

    public static class keygen256
        extends keygen
    {
        public keygen256()
        {
            super(256);
        }
    }

    public static class algparamgen
        extends basealgorithmparametergenerator
    {
        protected void engineinit(
            algorithmparameterspec genparamspec,
            securerandom random)
            throws invalidalgorithmparameterexception
        {
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for camellia parameter generation.");
        }

        protected algorithmparameters enginegenerateparameters()
        {
            byte[] iv = new byte[16];

            if (random == null)
            {
                random = new securerandom();
            }

            random.nextbytes(iv);

            algorithmparameters params;

            try
            {
                params = algorithmparameters.getinstance("camellia", bouncycastleprovider.provider_name);
                params.init(new ivparameterspec(iv));
            }
            catch (exception e)
            {
                throw new runtimeexception(e.getmessage());
            }

            return params;
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "camellia iv";
        }
    }

    public static class mappings
        extends symmetricalgorithmprovider
    {
        private static final string prefix = camellia.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("algorithmparameters.camellia", prefix + "$algparams");
            provider.addalgorithm("alg.alias.algorithmparameters." + nttobjectidentifiers.id_camellia128_cbc, "camellia");
            provider.addalgorithm("alg.alias.algorithmparameters." + nttobjectidentifiers.id_camellia192_cbc, "camellia");
            provider.addalgorithm("alg.alias.algorithmparameters." + nttobjectidentifiers.id_camellia256_cbc, "camellia");

            provider.addalgorithm("algorithmparametergenerator.camellia", prefix + "$algparamgen");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + nttobjectidentifiers.id_camellia128_cbc, "camellia");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + nttobjectidentifiers.id_camellia192_cbc, "camellia");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + nttobjectidentifiers.id_camellia256_cbc, "camellia");

            provider.addalgorithm("cipher.camellia", prefix + "$ecb");
            provider.addalgorithm("cipher." + nttobjectidentifiers.id_camellia128_cbc, prefix + "$cbc");
            provider.addalgorithm("cipher." + nttobjectidentifiers.id_camellia192_cbc, prefix + "$cbc");
            provider.addalgorithm("cipher." + nttobjectidentifiers.id_camellia256_cbc, prefix + "$cbc");

            provider.addalgorithm("cipher.camelliarfc3211wrap", prefix + "$rfc3211wrap");
            provider.addalgorithm("cipher.camelliawrap", prefix + "$wrap");
            provider.addalgorithm("alg.alias.cipher." + nttobjectidentifiers.id_camellia128_wrap, "camelliawrap");
            provider.addalgorithm("alg.alias.cipher." + nttobjectidentifiers.id_camellia192_wrap, "camelliawrap");
            provider.addalgorithm("alg.alias.cipher." + nttobjectidentifiers.id_camellia256_wrap, "camelliawrap");

            provider.addalgorithm("keygenerator.camellia", prefix + "$keygen");
            provider.addalgorithm("keygenerator." + nttobjectidentifiers.id_camellia128_wrap, prefix + "$keygen128");
            provider.addalgorithm("keygenerator." + nttobjectidentifiers.id_camellia192_wrap, prefix + "$keygen192");
            provider.addalgorithm("keygenerator." + nttobjectidentifiers.id_camellia256_wrap, prefix + "$keygen256");
            provider.addalgorithm("keygenerator." + nttobjectidentifiers.id_camellia128_cbc, prefix + "$keygen128");
            provider.addalgorithm("keygenerator." + nttobjectidentifiers.id_camellia192_cbc, prefix + "$keygen192");
            provider.addalgorithm("keygenerator." + nttobjectidentifiers.id_camellia256_cbc, prefix + "$keygen256");

            addgmacalgorithm(provider, "camellia", prefix + "$gmac", prefix + "$keygen");
        }
    }
}
