package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.gost28147engine;
import org.ripple.bouncycastle.crypto.macs.gost28147mac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.ivalgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class gost28147
{
    private gost28147()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new gost28147engine());
        }
    }

    public static class cbc
       extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new gost28147engine()), 64);
        }
    }

    /**
     * gost28147
     */
    public static class mac
        extends basemac
    {
        public mac()
        {
            super(new gost28147mac());
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
            super("gost28147", keysize, new cipherkeygenerator());
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
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for aes parameter generation.");
        }

        protected algorithmparameters enginegenerateparameters()
        {
            byte[]  iv = new byte[16];

            if (random == null)
            {
                random = new securerandom();
            }

            random.nextbytes(iv);

            algorithmparameters params;

            try
            {
                params = algorithmparameters.getinstance("gost28147", bouncycastleprovider.provider_name);
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
            return "gost iv";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = gost28147.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("cipher.gost28147", prefix + "$ecb");
            provider.addalgorithm("alg.alias.cipher.gost", "gost28147");
            provider.addalgorithm("alg.alias.cipher.gost-28147", "gost28147");
            provider.addalgorithm("cipher." + cryptoproobjectidentifiers.gostr28147_cbc, prefix + "$cbc");

            provider.addalgorithm("keygenerator.gost28147", prefix + "$keygen");
            provider.addalgorithm("alg.alias.keygenerator.gost", "gost28147");
            provider.addalgorithm("alg.alias.keygenerator.gost-28147", "gost28147");
            provider.addalgorithm("alg.alias.keygenerator." + cryptoproobjectidentifiers.gostr28147_cbc, "gost28147");

            provider.addalgorithm("mac.gost28147mac", prefix + "$mac");
            provider.addalgorithm("alg.alias.mac.gost28147", "gost28147mac");
        }
    }
}
