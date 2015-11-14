package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.io.ioexception;
import java.security.algorithmparameters;
import java.security.invalidalgorithmparameterexception;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.misc.ideacbcpar;
import org.ripple.bouncycastle.crypto.cipherkeygenerator;
import org.ripple.bouncycastle.crypto.engines.ideaengine;
import org.ripple.bouncycastle.crypto.macs.cbcblockciphermac;
import org.ripple.bouncycastle.crypto.macs.cfbblockciphermac;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparametergenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.baseblockcipher;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basekeygenerator;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basemac;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.pbesecretkeyfactory;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public final class idea
{
    private idea()
    {
    }
    
    public static class ecb
        extends baseblockcipher
    {
        public ecb()
        {
            super(new ideaengine());
        }
    }

    public static class cbc
       extends baseblockcipher
    {
        public cbc()
        {
            super(new cbcblockcipher(new ideaengine()), 64);
        }
    }

    public static class keygen
        extends basekeygenerator
    {
        public keygen()
        {
            super("idea", 128, new cipherkeygenerator());
        }
    }

    public static class pbewithshaandideakeygen
       extends pbesecretkeyfactory
    {
       public pbewithshaandideakeygen()
       {
           super("pbewithshaandidea-cbc", null, true, pkcs12, sha1, 128, 64);
       }
    }

    static public class pbewithshaandidea
        extends baseblockcipher
    {
        public pbewithshaandidea()
        {
            super(new cbcblockcipher(new ideaengine()));
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
            throw new invalidalgorithmparameterexception("no supported algorithmparameterspec for idea parameter generation.");
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
                params = algorithmparameters.getinstance("idea", bouncycastleprovider.provider_name);
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

        protected byte[] enginegetencoded()
            throws ioexception
        {
            return enginegetencoded("asn.1");
        }

        protected byte[] enginegetencoded(
            string format)
            throws ioexception
        {
            if (this.isasn1formatstring(format))
            {
                return new ideacbcpar(enginegetencoded("raw")).getencoded();
            }

            if (format.equals("raw"))
            {
                byte[]  tmp = new byte[iv.length];

                system.arraycopy(iv, 0, tmp, 0, iv.length);
                return tmp;
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

            throw new invalidparameterspecexception("unknown parameter spec passed to iv parameters object.");
        }

        protected void engineinit(
            algorithmparameterspec paramspec)
            throws invalidparameterspecexception
        {
            if (!(paramspec instanceof ivparameterspec))
            {
                throw new invalidparameterspecexception("ivparameterspec required to initialise a iv parameters algorithm parameters object");
            }

            this.iv = ((ivparameterspec)paramspec).getiv();
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
            if (format.equals("raw"))
            {
                engineinit(params);
                return;
            }
            if (format.equals("asn.1"))
            {
                asn1inputstream ain = new asn1inputstream(params);
                ideacbcpar      oct = new ideacbcpar((asn1sequence)ain.readobject());

                engineinit(oct.getiv());
                return;
            }

            throw new ioexception("unknown parameters format in iv parameters object");
        }

        protected string enginetostring()
        {
            return "idea parameters";
        }
    }
    
    public static class mac
        extends basemac
    {
        public mac()
        {
            super(new cbcblockciphermac(new ideaengine()));
        }
    }

    public static class cfb8mac
        extends basemac
    {
        public cfb8mac()
        {
            super(new cfbblockciphermac(new ideaengine()));
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = idea.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("algorithmparametergenerator.idea", prefix + "$algparamgen");
            provider.addalgorithm("algorithmparametergenerator.1.3.6.1.4.1.188.7.1.1.2", prefix + "$algparamgen");
            provider.addalgorithm("algorithmparameters.idea", prefix + "$algparams");
            provider.addalgorithm("algorithmparameters.1.3.6.1.4.1.188.7.1.1.2", prefix + "$algparams");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaandidea", "pkcs12pbe");
            provider.addalgorithm("alg.alias.algorithmparameters.pbewithshaandidea-cbc", "pkcs12pbe");
            provider.addalgorithm("cipher.idea", prefix + "$ecb");
            provider.addalgorithm("cipher.1.3.6.1.4.1.188.7.1.1.2", prefix + "$cbc");
            provider.addalgorithm("cipher.pbewithshaandidea-cbc", prefix + "$pbewithshaandidea");
            provider.addalgorithm("keygenerator.idea", prefix + "$keygen");
            provider.addalgorithm("keygenerator.1.3.6.1.4.1.188.7.1.1.2", prefix + "$keygen");
            provider.addalgorithm("secretkeyfactory.pbewithshaandidea-cbc", prefix + "$pbewithshaandideakeygen");
            provider.addalgorithm("mac.ideamac", prefix + "$mac");
            provider.addalgorithm("alg.alias.mac.idea", "ideamac");
            provider.addalgorithm("mac.ideamac/cfb8", prefix + "$cfb8mac");
            provider.addalgorithm("alg.alias.mac.idea/cfb8", "ideamac/cfb8");
        }
    }
}
