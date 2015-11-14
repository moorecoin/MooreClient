package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.rc532engine;
import org.ripple.bouncycastle.crypto.engines.rc564engine;
import org.ripple.bouncycastle.crypto.macs.cbcblockciphermac;
import org.ripple.bouncycastle.crypto.macs.cfbblockciphermac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class rc5
{
    private rc5()
    {
    }

    /**
     * rc5
     */
    public static class ecb32
        extends baseblockcipher
    {
        public ecb32()
        {
            super(new rc532engine());
        }
    }

    /**
     * rc564
     */
    public static class ecb64
        extends baseblockcipher
    {
        public ecb64()
        {
            super(new rc564engine());
        }
    }

    public static class cbc32
       extends baseblockcipher
    {
        public cbc32()
        {
            super(new cbcblockcipher(new rc532engine()), 64);
        }
    }

    public static class keygen32
        extends basekeygenerator
    {
        public keygen32()
        {
            super("rc5", 128, new cipherkeygenerator());
        }
    }

    /**
     * rc5
     */
    public static class keygen64
        extends basekeygenerator
    {
        public keygen64()
        {
            super("rc5-64", 256, new cipherkeygenerator());
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
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for rc5 parameter generation.");
        }

        protected algorithmparameters enginegenerateparameters()
        {
            byte[] iv = new byte[8];

            if (random == null)
            {
                random = new securerandom();
            }

            random.nextbytes(iv);

            algorithmparameters params;

            try
            {
                params = algorithmparameters.getinstance("rc5", bouncycastleprovider.provider_name);
                params.init(new ivparameterspec(iv));
            }
            catch (exception e)
            {
                throw new runtimeexception(e.getmessage());
            }

            return params;
        }
    }

    public static class mac32
        extends basemac
    {
        public mac32()
        {
            super(new cbcblockciphermac(new rc532engine()));
        }
    }

    public static class cfb8mac32
        extends basemac
    {
        public cfb8mac32()
        {
            super(new cfbblockciphermac(new rc532engine()));
        }
    }

    public static class algparams
        extends ivalgorithmparameters
    {
        protected string enginetostring()
        {
            return "rc5 iv";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = rc5.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("cipher.rc5", prefix + "$ecb32");
            provider.addalgorithm("alg.alias.cipher.rc5-32", "rc5");
            provider.addalgorithm("cipher.rc5-64", prefix + "$ecb64");
            provider.addalgorithm("keygenerator.rc5", prefix + "$keygen32");
            provider.addalgorithm("alg.alias.keygenerator.rc5-32", "rc5");
            provider.addalgorithm("keygenerator.rc5-64", prefix + "$keygen64");
            provider.addalgorithm("algorithmparameters.rc5", prefix + "$algparams");
            provider.addalgorithm("algorithmparameters.rc5-64", prefix + "$algparams");
            provider.addalgorithm("mac.rc5mac", prefix + "$mac32");
            provider.addalgorithm("alg.alias.mac.rc5", "rc5mac");
            provider.addalgorithm("mac.rc5mac/cfb8", prefix + "$cfb8mac32");
            provider.addalgorithm("alg.alias.mac.rc5/cfb8", "rc5mac/cfb8");

        }
    }
}
