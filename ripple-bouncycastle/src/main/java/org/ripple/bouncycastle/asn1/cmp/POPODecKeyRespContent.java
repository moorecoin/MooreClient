package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;

public class popodeckeyrespcontent
    extends asn1object
{
    private asn1sequence content;

    private popodeckeyrespcontent(asn1sequence seq)
    {
        content = seq;
    }

    public static popodeckeyrespcontent getinstance(object o)
    {
        if (o instanceof popodeckeyrespcontent)
        {
            return (popodeckeyrespcontent)o;
        }

        if (o != null)
        {
            return new popodeckeyrespcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public asn1integer[] toasn1integerarray()
    {
        asn1integer[] result = new asn1integer[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = asn1integer.getinstance(content.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * popodeckeyrespcontent ::= sequence of integer
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
