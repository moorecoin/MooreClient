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

public class pkcs12pbeparams
    extends asn1object
{
    asn1integer      iterations;
    asn1octetstring iv;

    public pkcs12pbeparams(
        byte[]      salt,
        int         iterations)
    {
        this.iv = new deroctetstring(salt);
        this.iterations = new asn1integer(iterations);
    }

    private pkcs12pbeparams(
        asn1sequence  seq)
    {
        iv = (asn1octetstring)seq.getobjectat(0);
        iterations = asn1integer.getinstance(seq.getobjectat(1));
    }

    public static pkcs12pbeparams getinstance(
        object  obj)
    {
        if (obj instanceof pkcs12pbeparams)
        {
            return (pkcs12pbeparams)obj;
        }
        else if (obj != null)
        {
            return new pkcs12pbeparams(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public biginteger getiterations()
    {
        return iterations.getvalue();
    }

    public byte[] getiv()
    {
        return iv.getoctets();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(iv);
        v.add(iterations);

        return new dersequence(v);
    }
}
