package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.io.ioexception;
import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.misc.cast5cbcparameters;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.cast5engine;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class cast5
{
    private cast5()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new cast5engine());
        }
    }

    public static class cbc
       extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new cast5engine()), 64);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("cast5", 128, new cipherkeygenerator());
        }
    }

    public static class algparamgen
        extends basealgorithmparametergenerator
    {
        protected void engineinit(
            algorithmparameterspec  genparamspec,
            securerandom            random)
            throws invalidalgorithmparameterexception
        {
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for cast5 parameter generation.");
        }

        protected algorithmparameters enginegenerateparameters()
        {
            byte[]  iv = new byte[8];

            if (random == null)
            {
                random = new securerandom();
            }

            random.nextbytes(iv);

            algorithmparameters params;

            try
            {
                params = algorithmparameters.getinstance("cast5", bouncycastleprovider.provider_name);
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
        extends basealgorithmparameters
    {
        private byte[]  iv;
        private int     keylength = 128;

        protected byte[] enginegetencoded()
        {
            byte[]  tmp = new byte[iv.length];

            system.arraycopy(iv, 0, tmp, 0, iv.length);
            return tmp;
        }

        protected byte[] enginegetencoded(
            string format)
            throws ioexception
        {
            if (this.isasn1formatstring(format))
            {
                return new cast5cbcparameters(enginegetencoded(), keylength).getencoded();
            }

            if (format.equals("raw"))
            {
                return enginegetencoded();
            }


            return null;
        }

        protected algorithmparameterspec localenginegetparameterspec(
            class paramspec)
            throws invalidparameterspecexception
        {
            if (paramspec == ivparameterspec.class)
            {
                return new ivparameterspec(iv);
            }

            throw new invalidparameterspecexception("unknown parameter spec passed to cast5 parameters object.");
        }

        protected void engineinit(
            algorithmparameterspec paramspec)
            throws invalidparameterspecexception
        {
            if (paramspec instanceof ivparameterspec)
            {
                this.iv = ((ivparameterspec)paramspec).getiv();
            }
            else
            {
                throw new invalidparameterspecexception("ivparameterspec required to initialise a cast5 parameters algorithm parameters object");
            }
        }

        protected void engineinit(
            byte[] params)
            throws ioexception
        {
            this.iv = new byte[params.length];

            system.arraycopy(params, 0, iv, 0, iv.length);
        }

        protected void engineinit(
            byte[] params,
            string format)
            throws ioexception
        {
            if (this.isasn1formatstring(format))
            {
                asn1inputstream ain = new asn1inputstream(params);
                cast5cbcparameters      p = cast5cbcparameters.getinstance(ain.readobject());

                keylength = p.getkeylength();

                iv = p.getiv();

                return;
            }

            if (format.equals("raw"))
            {
                engineinit(params);
                return;
            }

            throw new ioexception("unknown parameters format in iv parameters object");
        }

        protected string enginetostring()
        {
            return "cast5 parameters";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = cast5.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {

            provider.addalgorithm("algorithmparameters.cast5", prefix + "$algparams");
            provider.addalgorithm("alg.alias.algorithmparameters.1.2.840.113533.7.66.10", "cast5");

            provider.addalgorithm("algorithmparametergenerator.cast5", prefix + "$algparamgen");
            provider.addalgorithm("alg.alias.algorithmparametergenerator.1.2.840.113533.7.66.10", "cast5");

            provider.addalgorithm("cipher.cast5", prefix + "$ecb");
            provider.addalgorithm("cipher.1.2.840.113533.7.66.10", prefix + "$cbc");

            provider.addalgorithm("keygenerator.cast5", prefix + "$keygen");
            provider.addalgorithm("alg.alias.keygenerator.1.2.840.113533.7.66.10", "cast5");

        }
    }
}
