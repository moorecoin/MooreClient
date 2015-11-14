package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.noekeonengine;
import org.ripple.bouncycastle.crypto.macs.gmac;
import org.ripple.bouncycastle.crypto.modes.gcmblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class noekeon
{
    private noekeon()
    {
    }

    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new noekeonengine());
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("noekeon", 128, new cipherkeygenerator());
        }
    }

    public static class gmac
        extends basemac
    {
        public gmac()
        {
            super(new gmac(new gcmblockcipher(new noekeonengine())));
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
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for noekeon parameter generation.");
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
                params = algorithmparameters.getinstance("noekeon", bouncycastleprovider.provider_name);
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
            return "noekeon iv";
        }
    }

    public static class mappings
        extends symmetricalgorithmprovider
    {
        private static final string prefix = noekeon.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("algorithmparameters.noekeon", prefix + "$algparams");

            provider.addalgorithm("algorithmparametergenerator.noekeon", prefix + "$algparamgen");

            provider.addalgorithm("cipher.noekeon", prefix + "$ecb");

            provider.addalgorithm("keygenerator.noekeon", prefix + "$keygen");

            addgmacalgorithm(provider, "noekeon", prefix + "$gmac", prefix + "$keygen");
        }
    }
}
