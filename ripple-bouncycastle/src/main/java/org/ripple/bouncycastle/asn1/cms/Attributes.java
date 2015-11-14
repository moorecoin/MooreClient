package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.dlset;

public class attributes
    extends asn1object
{
    private asn1set attributes;

    private attributes(asn1set set)
    {
        attributes = set;
    }

    public attributes(asn1encodablevector v)
    {
        attributes = new dlset(v);
    }

    public static attributes getinstance(object obj)
    {
        if (obj instanceof attributes)
        {
            return (attributes)obj;
        }
        else if (obj != null)
        {
            return new attributes(asn1set.getinstance(obj));
        }

        return null;
    }

    public attribute[] getattributes()
    {
        attribute[] rv = new attribute[attributes.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = attribute.getinstance(attributes.getobjectat(i));
        }

        return rv;
    }

    /**
     * <pre>
     * attributes ::=
     *   set size(1..max) of attribute -- according to rfc 5652
     * </pre>
     * @return
     */
    public asn1primitive toasn1primitive()
    {
        return attributes;
    }
}
