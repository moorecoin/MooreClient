package org.ripple.bouncycastle.jcajce.provider.symmetric;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import javax.crypto.spec.pbeparameterspec;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.pkcs.pkcs12pbeparams;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparameters;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;

public class pbepkcs12
{
    private pbepkcs12()
    {

    }

    public static class algparams
        extends basealgorithmparameters
    {
        pkcs12pbeparams params;

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
                return new pbeparameterspec(params.getiv(),
                    params.getiterations().intvalue());
            }

            throw new invalidparameterspecexception("unknown parameter spec passed to pkcs12 pbe parameters object.");
        }

        protected void engineinit(
            algorithmparameterspec paramspec)
            throws invalidparameterspecexception
        {
            if (!(paramspec instanceof pbeparameterspec))
            {
                throw new invalidparameterspecexception("pbeparameterspec required to initialise a pkcs12 pbe parameters algorithm parameters object");
            }

            pbeparameterspec pbespec = (pbeparameterspec)paramspec;

            this.params = new pkcs12pbeparams(pbespec.getsalt(),
                pbespec.getiterationcount());
        }

        protected void engineinit(
            byte[] params)
            throws ioexception
        {
            this.params = pkcs12pbeparams.getinstance(asn1primitive.frombytearray(params));
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

            throw new ioexception("unknown parameters format in pkcs12 pbe parameters object");
        }

        protected string enginetostring()
        {
            return "pkcs12 pbe parameters";
        }
    }

    public static class mappings
        extends algorithmprovider
    {
        private static final string prefix = pbepkcs12.class.getname();

        public mappings()
        {
        }

        public void configure(configurableprovider provider)
        {
            provider.addalgorithm("algorithmparameters.pkcs12pbe", prefix + "$algparams");
        }
    }
}
