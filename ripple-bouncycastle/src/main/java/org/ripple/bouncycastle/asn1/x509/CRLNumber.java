package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;

/**
 * the crlnumber object.
 * <pre>
 * crlnumber::= integer(0..max)
 * </pre>
 */
public class crlnumber
    extends asn1object
{
    private biginteger number;

    public crlnumber(
        biginteger number)
    {
        this.number = number;
    }

    public biginteger getcrlnumber()
    {
        return number;
    }

    public string tostring()
    {
        return "crlnumber: " + getcrlnumber();
    }

    public asn1primitive toasn1primitive()
    {
        return new asn1integer(number);
    }

    public static crlnumber getinstance(object o)
    {
        if (o instanceof crlnumber)
        {
            return (crlnumber)o;
        }
        else if (o != null)
        {
            return new crlnumber(asn1integer.getinstance(o).getvalue());
        }

        return null;
    }
}
