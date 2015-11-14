package org.ripple.bouncycastle.jcajce.provider.asymmetric.ies;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.jce.spec.iesparameterspec;

public class algorithmparametersspi
    extends java.security.algorithmparametersspi
{
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

    iesparameterspec currentspec;

    /**
     * in the absence of a standard way of doing it this will do for
     * now...
     */
    protected byte[] enginegetencoded()
    {
        try
        {
            asn1encodablevector v = new asn1encodablevector();

            v.add(new deroctetstring(currentspec.getderivationv()));
            v.add(new deroctetstring(currentspec.getencodingv()));
            v.add(new derinteger(currentspec.getmackeysize()));

            return new dersequence(v).getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new runtimeexception("error encoding iesparameters");
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
        if (paramspec == iesparameterspec.class)
        {
            return currentspec;
        }

        throw new invalidparameterspecexception("unknown parameter spec passed to elgamal parameters object.");
    }

    protected void engineinit(
        algorithmparameterspec paramspec)
        throws invalidparameterspecexception
    {
        if (!(paramspec instanceof iesparameterspec))
        {
            throw new invalidparameterspecexception("iesparameterspec required to initialise a ies algorithm parameters object");
        }

        this.currentspec = (iesparameterspec)paramspec;
    }

    protected void engineinit(
        byte[] params)
        throws ioexception
    {
        try
        {
            asn1sequence s = (asn1sequence)asn1primitive.frombytearray(params);

            this.currentspec = new iesparameterspec(
                ((asn1octetstring)s.getobjectat(0)).getoctets(),
                ((asn1octetstring)s.getobjectat(0)).getoctets(),
                ((derinteger)s.getobjectat(0)).getvalue().intvalue());
        }
        catch (classcastexception e)
        {
            throw new ioexception("not a valid ies parameter encoding.");
        }
        catch (arrayindexoutofboundsexception e)
        {
            throw new ioexception("not a valid ies parameter encoding.");
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
        return "ies parameters";
    }
}
