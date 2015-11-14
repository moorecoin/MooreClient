package org.ripple.bouncycastle.asn1.pkcs;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class rc2cbcparameter
    extends asn1object
{
    asn1integer      version;
    asn1octetstring iv;

    public static rc2cbcparameter getinstance(
        object  o)
    {
        if (o instanceof rc2cbcparameter)
        {
            return (rc2cbcparameter)o;
        }
        if (o != null)
        {
            return new rc2cbcparameter(asn1sequence.getinstance(o));
        }

        return null;
    }

    public rc2cbcparameter(
        byte[]  iv)
    {
        this.version = null;
        this.iv = new deroctetstring(iv);
    }

    public rc2cbcparameter(
        int     parameterversion,
        byte[]  iv)
    {
        this.version = new asn1integer(parameterversion);
        this.iv = new deroctetstring(iv);
    }

    private rc2cbcparameter(
        asn1sequence  seq)
    {
        if (seq.size() == 1)
        {
            version = null;
            iv = (asn1octetstring)seq.getobjectat(0);
        }
        else
        {
            version = (asn1integer)seq.getobjectat(0);
            iv = (asn1octetstring)seq.getobjectat(1);
        }
    }

    public biginteger getrc2parameterversion()
    {
        if (version == null)
        {
            return null;
        }

        return version.getvalue();
    }

    public byte[] getiv()
    {
        return iv.getoctets();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        if (version != null)
        {
            v.add(version);
        }

        v.add(iv);

        return new dersequence(v);
    }
}
