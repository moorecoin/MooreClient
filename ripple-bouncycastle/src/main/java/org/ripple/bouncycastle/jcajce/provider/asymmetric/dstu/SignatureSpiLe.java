package org.ripple.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.io.ioexception;
import java.security.signatureexception;

import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.deroctetstring;

public class signaturespile
    extends signaturespi
{
    void reversebytes(byte[] bytes)
    {
        byte tmp;

        for (int i = 0; i < bytes.length / 2; i++)
        {
            tmp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = tmp;
        }
    }

    protected byte[] enginesign()
        throws signatureexception
    {
        byte[] signature = asn1octetstring.getinstance(super.enginesign()).getoctets();
        reversebytes(signature);
        try
        {
            return (new deroctetstring(signature)).getencoded();
        }
        catch (exception e)
        {
            throw new signatureexception(e.tostring());
        }
    }

    protected boolean engineverify(
        byte[] sigbytes)
        throws signatureexception
    {
        byte[] bytes = null;

        try
        {
            bytes = ((asn1octetstring)asn1octetstring.frombytearray(sigbytes)).getoctets();
        }
        catch (ioexception e)
        {
            throw new signatureexception("error decoding signature bytes.");
        }

        reversebytes(bytes);

        try
        {
            return super.engineverify((new deroctetstring(bytes)).getencoded());
        }
        catch (signatureexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new signatureexception(e.tostring());
        }
    }
}
