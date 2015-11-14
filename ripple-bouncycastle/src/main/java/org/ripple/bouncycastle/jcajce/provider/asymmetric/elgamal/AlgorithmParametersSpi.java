package org.ripple.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import javax.crypto.spec.dhparameterspec;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.oiw.elgamalparameter;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.basealgorithmparameters;
import org.ripple.bouncycastle.jce.spec.elgamalparameterspec;

public class algorithmparametersspi
    extends basealgorithmparameters
{
    elgamalparameterspec currentspec;

    /**
     * return the x.509 asn.1 structure elgamalparameter.
     * <p/>
     * <pre>
     *  elgamalparameter ::= sequence {
     *                   prime integer, -- p
     *                   base integer, -- g}
     * </pre>
     */
    protected byte[] enginegetencoded()
    {
        elgamalparameter elp = new elgamalparameter(currentspec.getp(), currentspec.getg());

        try
        {
            return elp.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new runtimeexception("error encoding elgamalparameters");
        }
    }

    protected byte[] enginegetencoded(
        string format)
    {
        if (isasn1formatstring(format) || format.equalsignorecase("x.509"))
        {
            return enginegetencoded();
        }

        return null;
    }

    protected algorithmparameterspec localenginegetparameterspec(
        class paramspec)
        throws invalidparameterspecexception
    {
        if (paramspec == elgamalparameterspec.class)
        {
            return currentspec;
        }
        else if (paramspec == dhparameterspec.class)
        {
            return new dhparameterspec(currentspec.getp(), currentspec.getg());
        }

        throw new invalidparameterspecexception("unknown parameter spec passed to elgamal parameters object.");
    }

    protected void engineinit(
        algorithmparameterspec paramspec)
        throws invalidparameterspecexception
    {
        if (!(paramspec instanceof elgamalparameterspec) && !(paramspec instanceof dhparameterspec))
        {
            throw new invalidparameterspecexception("dhparameterspec required to initialise a elgamal algorithm parameters object");
        }

        if (paramspec instanceof elgamalparameterspec)
        {
            this.currentspec = (elgamalparameterspec)paramspec;
        }
        else
        {
            dhparameterspec s = (dhparameterspec)paramspec;

            this.currentspec = new elgamalparameterspec(s.getp(), s.getg());
        }
    }

    protected void engineinit(
        byte[] params)
        throws ioexception
    {
        try
        {
            elgamalparameter elp = new elgamalparameter((asn1sequence)asn1primitive.frombytearray(params));

            currentspec = new elgamalparameterspec(elp.getp(), elp.getg());
        }
        catch (classcastexception e)
        {
            throw new ioexception("not a valid elgamal parameter encoding.");
        }
        catch (arrayindexoutofboundsexception e)
        {
            throw new ioexception("not a valid elgamal parameter encoding.");
        }
    }

    protected void engineinit(
        byte[] params,
        string format)
        throws ioexception
    {
        if (isasn1formatstring(format) || format.equalsignorecase("x.509"))
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
        return "elgamal parameters";
    }
}
