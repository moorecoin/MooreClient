package org.ripple.bouncycastle.jcajce.provider.asymmetric.dh;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import javax.crypto.spec.dhparameterspec;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.pkcs.dhparameter;

public class algorithmparametersspi
    extends java.security.algorithmparametersspi
{
    dhparameterspec     currentspec;

    protected boolean isasn1formatstring(string format)
    {
        return format == null || format.equals("asn.1");
    }

    protected algorithmparameterspec enginegetparameterspec(
        class paramspec)
        throws invalidparameterspecexception
    {
        if (paramspec == null)
        {
            throw new nullpointerexception("argument to getparameterspec must not be null");
        }

        return localenginegetparameterspec(paramspec);
    }




        /**
         * return the pkcs#3 asn.1 structure dhparameter.
         * <p>
         * <pre>
         *  dhparameter ::= sequence {
         *                   prime integer, -- p
         *                   base integer, -- g
         *                   privatevaluelength integer optional}
         * </pre>
         */
        protected byte[] enginegetencoded() 
        {
            dhparameter dhp = new dhparameter(currentspec.getp(), currentspec.getg(), currentspec.getl());

            try
            {
                return dhp.getencoded(asn1encoding.der);
            }
            catch (ioexception e)
            {
                throw new runtimeexception("error encoding dhparameters");
            }
        }

        protected byte[] enginegetencoded(
            string format) 
        {
            if (isasn1formatstring(format))
            {
                return enginegetencoded();
            }

            return null;
        }

        protected algorithmparameterspec localenginegetparameterspec(
            class paramspec) 
            throws invalidparameterspecexception
        {
            if (paramspec == dhparameterspec.class)
            {
                return currentspec;
            }

            throw new invalidparameterspecexception("unknown parameter spec passed to dh parameters object.");
        }

        protected void engineinit(
            algorithmparameterspec paramspec) 
            throws invalidparameterspecexception
        {
            if (!(paramspec instanceof dhparameterspec))
            {
                throw new invalidparameterspecexception("dhparameterspec required to initialise a diffie-hellman algorithm parameters object");
            }

            this.currentspec = (dhparameterspec)paramspec;
        }

        protected void engineinit(
            byte[] params) 
            throws ioexception
        {
            try
            {
                dhparameter dhp = dhparameter.getinstance(params);

                if (dhp.getl() != null)
                {
                    currentspec = new dhparameterspec(dhp.getp(), dhp.getg(), dhp.getl().intvalue());
                }
                else
                {
                    currentspec = new dhparameterspec(dhp.getp(), dhp.getg());
                }
            }
            catch (classcastexception e)
            {
                throw new ioexception("not a valid dh parameter encoding.");
            }
            catch (arrayindexoutofboundsexception e)
            {
                throw new ioexception("not a valid dh parameter encoding.");
            }
        }

        protected void engineinit(
            byte[] params,
            string format) 
            throws ioexception
        {
            if (isasn1formatstring(format))
            {
                engineinit(params);
            }
            else
            {
                throw new ioexception("unknown parameter format " + format);
            }
        }

        protected string enginetostring() 
        {
            return "diffie-hellman parameters";
        }
}
