package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import javax.crypto.spec.pbeparameterspec;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.pkcs.pbkdf2params;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public class pbepbkdf2
{
    private pbepbkdf2()
    {

    }

    public static class algparams
        extends basealgorithmparameters
    {
        pbkdf2params params;

        protected byte[] enginegetencoded()
        {
            try
            {
                return params.getencoded(asn1encoding.der);
            }
            catch (ioexception e)
            {
                throw new runtimeexception("oooops! " + e.tostring());
            }
        }

        protected byte[] enginegetencoded(
            string format)
        {
            if (this.isasn1formatstring(format))
            {
                return enginegetencoded();
            }

            return null;
        }

        protected algorithmparameterspec localenginegetparameterspec(
            class paramspec)
            throws invalidparameterspecexception
        {
            if (paramspec == pbeparameterspec.class)
            {
                return new pbeparameterspec(params.getsalt(),
                                params.getiterationcount().intvalue());
            }

            throw new invalidparameterspecexception("unknown parameter spec passed to pbkdf2 pbe parameters object.");
        }

        protected void engineinit(
            algorithmparameterspec paramspec)
            throws invalidparameterspecexception
        {
            if (!(paramspec instanceof pbeparameterspec))
            {
                throw new invalidparameterspecexception("pbeparameterspec required to initialise a pbkdf2 pbe parameters algorithm parameters object");
            }

            pbeparameterspec    pbespec = (pbeparameterspec)paramspec;

            this.params = new pbkdf2params(pbespec.getsalt(),
                                pbespec.getiterationcount());
        }

        protected void engineinit(
            byte[] params)
            throws ioexception
        {
            this.params = pbkdf2params.getinstance(asn1primitive.frombytearray(params));
        }

        protected void engineinit(
            byte[] params,
            string format)
            throws ioexception
        {
            if (this.isasn1formatstring(format))
            {
                engineinit(params);
                return;
            }

            throw new ioexception("unknown parameters format in pbkdf2 parameters object");
        }

        protected string enginetostring()
        {
            return "pbkdf2 parameters";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = pbepbkdf2.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("algorithmparameters.pbkdf2", prefix + "$algparams");
            provider.addalgorithm("alg.alias.algorithmparameters." + pkcsobjectidentifiers.id_pbkdf2, "pbkdf2");
        }
    }
}
