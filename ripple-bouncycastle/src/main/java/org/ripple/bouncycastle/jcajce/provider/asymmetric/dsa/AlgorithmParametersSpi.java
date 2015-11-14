package org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.dsaparameterspec;
import java.security.spec.invalidparameterspecexception;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.x509.dsaparameter;

public class algorithmparametersspi
    extends java.security.algorithmparametersspi
{
    dsaparameterspec currentspec;

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
     * return the x.509 asn.1 structure dsaparameter.
     * <p/>
     * <pre>
     *  dsaparameter ::= sequence {
     *                   prime integer, -- p
     *                   subprime integer, -- q
     *                   base integer, -- g}
     * </pre>
     */
    protected byte[] enginegetencoded()
    {
        dsaparameter dsap = new dsaparameter(currentspec.getp(), currentspec.getq(), currentspec.getg());

        try
        {
            return dsap.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new runtimeexception("error encoding dsaparameters");
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
        if (paramspec == dsaparameterspec.class)
        {
            return currentspec;
        }

        throw new invalidparameterspecexception("unknown parameter spec passed to dsa parameters object.");
    }

    protected void engineinit(
        algorithmparameterspec paramspec)
        throws invalidparameterspecexception
    {
        if (!(paramspec instanceof dsaparameterspec))
        {
            throw new invalidparameterspecexception("dsaparameterspec required to initialise a dsa algorithm parameters object");
        }

        this.currentspec = (dsaparameterspec)paramspec;
    }

    protected void engineinit(
        byte[] params)
        throws ioexception
    {
        try
        {
            dsaparameter dsap = dsaparameter.getinstance(asn1primitive.frombytearray(params));

            currentspec = new dsaparameterspec(dsap.getp(), dsap.getq(), dsap.getg());
        }
        catch (classcastexception e)
        {
            throw new ioexception("not a valid dsa parameter encoding.");
        }
        catch (arrayindexoutofboundsexception e)
        {
            throw new ioexception("not a valid dsa parameter encoding.");
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
        return "dsa parameters";
    }
}
