package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.asn1.kisa.kisaobjectidentifiers;
import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.seedengine;
import org.ripple.bouncycastle.crypto.engines.seedwrapengine;
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

public final class seed
{
    private seed()
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
                    return new seedengine();
                }
            });
        }
    }

    public static class cbc
       extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new seedengine()), 128);
        }
    }

    public static class wrap
        extends basewrapcipher
    {
        public wrap()
        {
            super(new seedwrapengine());
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("seed", 128, new cipherkeygenerator());
        }
    }

    public static class gmac
        extends basemac
    {
        public gmac()
        {
            super(new gmac(new gcmblockcipher(new seedengine())));
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
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for seed parameter generation.");
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
                params = algorithmparameters.getinstance("seed", bouncycastleprovider.provider_name);
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
            return "seed iv";
        }
    }

    public static class mappings
        extends symmetricalgorithmprovider
    {
        private static final string prefix = seed.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("algorithmparameters.seed", prefix + "$algparams");
            provider.addalgorithm("alg.alias.algorithmparameters." + kisaobjectidentifiers.id_seedcbc, "seed");

            provider.addalgorithm("algorithmparametergenerator.seed", prefix + "$algparamgen");
            provider.addalgorithm("alg.alias.algorithmparametergenerator." + kisaobjectidentifiers.id_seedcbc, "seed");

            provider.addalgorithm("cipher.seed", prefix + "$ecb");
            provider.addalgorithm("cipher." + kisaobjectidentifiers.id_seedcbc, prefix + "$cbc");

            provider.addalgorithm("cipher.seedwrap", prefix + "$wrap");
            provider.addalgorithm("alg.alias.cipher." + kisaobjectidentifiers.id_npki_app_cmsseed_wrap, "seedwrap");

            provider.addalgorithm("keygenerator.seed", prefix + "$keygen");
            provider.addalgorithm("keygenerator." + kisaobjectidentifiers.id_seedcbc, prefix + "$keygen");
            provider.addalgorithm("keygenerator." + kisaobjectidentifiers.id_npki_app_cmsseed_wrap, prefix + "$keygen");

            addgmacalgorithm(provider, "seed", prefix + "$gmac", prefix + "$keygen");
        }
    }
}
