package org.ripple.bouncycastle.asn1.ess;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.deroctetstring;

public class contentidentifier
    extends asn1object
{
     asn1octetstring value;

    public static contentidentifier getinstance(object o)
    {
        if (o instanceof contentidentifier)
        {
            return (contentidentifier) o;
        }
        else if (o != null)
        {
            return new contentidentifier(asn1octetstring.getinstance(o));
        }

        return null;
    }

    /**
     * create from octet string whose octets represent the identifier.
     */
    private contentidentifier(
        asn1octetstring value)
    {
        this.value = value;
    }

    /**
     * create from byte array representing the identifier.
     */
    public contentidentifier(
        byte[] value)
    {
        this(new deroctetstring(value));
    }
    
    public asn1octetstring getvalue()
    {
        return value;
    }

    /**
     * the definition of contentidentifier is
     * <pre>
     * contentidentifier ::=  octet string
     * </pre>
     * id-aa-contentidentifier object identifier ::= { iso(1)
     *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
     *  smime(16) id-aa(2) 7 }
     */
    public asn1primitive toasn1primitive()
    {
        return value;
    }
}
