package org.ripple.bouncycastle.jcajce.provider.asymmetric.gost;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.cryptopro.gost3410publickeyalgparameters;
import org.ripple.bouncycastle.jce.spec.gost3410parameterspec;
import org.ripple.bouncycastle.jce.spec.gost3410publickeyparametersetspec;

public class algorithmparametersspi
    extends java.security.algorithmparametersspi
{
    gost3410parameterspec currentspec;

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
     * return the x.509 asn.1 structure gost3410parameter.
     * <p/>
     * <pre>
     *  gost3410parameter ::= sequence {
     *                   prime integer, -- p
     *                   subprime integer, -- q
     *                   base integer, -- a}
     * </pre>
     */
    protected byte[] enginegetencoded()
    {
        gost3410publickeyalgparameters gost3410p = new gost3410publickeyalgparameters(new asn1objectidentifier(currentspec.getpublickeyparamsetoid()), new asn1objectidentifier(currentspec.getdigestparamsetoid()), new asn1objectidentifier(currentspec.getencryptionparamsetoid()));

        try
        {
            return gost3410p.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new runtimeexception("error encoding gost3410parameters");
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
        if (paramspec == gost3410publickeyparametersetspec.class)
        {
            return currentspec;
        }

        throw new invalidparameterspecexception("unknown parameter spec passed to gost3410 parameters object.");
    }

    protected void engineinit(
        algorithmparameterspec paramspec)
        throws invalidparameterspecexception
    {
        if (!(paramspec instanceof gost3410parameterspec))
        {
            throw new invalidparameterspecexception("gost3410parameterspec required to initialise a gost3410 algorithm parameters object");
        }

        this.currentspec = (gost3410parameterspec)paramspec;
    }

    protected void engineinit(
        byte[] params)
        throws ioexception
    {
        try
        {
            asn1sequence seq = (asn1sequence)asn1primitive.frombytearray(params);

            this.currentspec = gost3410parameterspec.frompublickeyalg(
                new gost3410publickeyalgparameters(seq));
        }
        catch (classcastexception e)
        {
            throw new ioexception("not a valid gost3410 parameter encoding.");
        }
        catch (arrayindexoutofboundsexception e)
        {
            throw new ioexception("not a valid gost3410 parameter encoding.");
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
        return "gost3410 parameters";
    }

}
