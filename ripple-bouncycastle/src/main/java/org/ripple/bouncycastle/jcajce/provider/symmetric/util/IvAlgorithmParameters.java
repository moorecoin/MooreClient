package org.ripple.bouncycastle.jcajce.provider.symmetric.util;

import java.io.ioexception;
import java.security.spec.algorithmparameterspec;
import java.security.spec.invalidparameterspecexception;

import javax.crypto.spec.ivparameterspec;

import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.util.arrays;

public class ivalgorithmparameters
    extends basealgorithmparameters
{
    private byte[] iv;

    protected byte[] enginegetencoded()
        throws ioexception
    {
        return enginegetencoded("asn.1");
    }

    protected byte[] enginegetencoded(
        string format)
        throws ioexception
    {
        if (isasn1formatstring(format))
        {
            return new deroctetstring(enginegetencoded("raw")).getencoded();
        }

        if (format.equals("raw"))
        {
            return arrays.clone(iv);
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
        //
        // check that we don't have a der encoded octet string
        //
        if ((params.length % 8) != 0
            && params[0] == 0x04 && params[1] == params.length - 2)
        {
            asn1octetstring oct = (asn1octetstring)asn1primitive.frombytearray(params);

            params = oct.getoctets();
        }

        this.iv = arrays.clone(params);
    }

    protected void engineinit(
        byte[] params,
        string format)
        throws ioexception
    {
        if (isasn1formatstring(format))
        {
            try
            {
                asn1octetstring oct = (asn1octetstring)asn1primitive.frombytearray(params);

                engineinit(oct.getoctets());
            }
            catch (exception e)
            {
                throw new ioexception("exception decoding: " + e);
            }

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
        return "iv parameters";
    }
}
