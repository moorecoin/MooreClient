package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x500.x500name;

public class responderid
    extends asn1object
    implements asn1choice
{
    private asn1encodable    value;

    public responderid(
        asn1octetstring    value)
    {
        this.value = value;
    }

    public responderid(
        x500name value)
    {
        this.value = value;
    }

    public static responderid getinstance(
        object  obj)
    {
        if (obj instanceof responderid)
        {
            return (responderid)obj;
        }
        else if (obj instanceof deroctetstring)
        {
            return new responderid((deroctetstring)obj);
        }
        else if (obj instanceof asn1taggedobject)
        {
            asn1taggedobject    o = (asn1taggedobject)obj;

            if (o.gettagno() == 1)
            {
                return new responderid(x500name.getinstance(o, true));
            }
            else
            {
                return new responderid(asn1octetstring.getinstance(o, true));
            }
        }

        return new responderid(x500name.getinstance(obj));
    }

    public static responderid getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(obj.getobject()); // must be explicitly tagged
    }

    public byte[] getkeyhash()
    {
        if (this.value instanceof asn1octetstring)
        {
            asn1octetstring octetstring = (asn1octetstring)this.value;
            return octetstring.getoctets();
        }

        return null;
    }

    public x500name getname()
    {
        if (this.value instanceof asn1octetstring)
        {
            return null;
        }

        return x500name.getinstance(value);
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * responderid ::= choice {
     *      byname          [1] name,
     *      bykey           [2] keyhash }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        if (value instanceof asn1octetstring)
        {
            return new dertaggedobject(true, 2, value);
        }

        return new dertaggedobject(true, 1, value);
    }
}
