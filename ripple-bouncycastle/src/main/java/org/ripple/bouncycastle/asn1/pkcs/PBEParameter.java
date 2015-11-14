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

public class pbeparameter
    extends asn1object
{
    asn1integer      iterations;
    asn1octetstring salt;

    public pbeparameter(
        byte[]      salt,
        int         iterations)
    {
        if (salt.length != 8)
        {
            throw new illegalargumentexception("salt length must be 8");
        }
        this.salt = new deroctetstring(salt);
        this.iterations = new asn1integer(iterations);
    }

    private pbeparameter(
        asn1sequence  seq)
    {
        salt = (asn1octetstring)seq.getobjectat(0);
        iterations = (asn1integer)seq.getobjectat(1);
    }

    public static pbeparameter getinstance(
        object  obj)
    {
        if (obj instanceof pbeparameter)
        {
            return (pbeparameter)obj;
        }
        else if (obj != null)
        {
            return new pbeparameter(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public biginteger getiterationcount()
    {
        return iterations.getvalue();
    }

    public byte[] getsalt()
    {
        return salt.getoctets();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(salt);
        v.add(iterations);

        return new dersequence(v);
    }
}
