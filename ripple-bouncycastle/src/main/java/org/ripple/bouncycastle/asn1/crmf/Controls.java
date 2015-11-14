package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class controls
    extends asn1object
{
    private asn1sequence content;

    private controls(asn1sequence seq)
    {
        content = seq;
    }

    public static controls getinstance(object o)
    {
        if (o instanceof controls)
        {
            return (controls)o;
        }

        if (o != null)
        {
            return new controls(asn1sequence.getinstance(o));
        }

        return null;
    }

    public controls(attributetypeandvalue atv)
    {
        content = new dersequence(atv);
    }

    public controls(attributetypeandvalue[] atvs)
    {
        asn1encodablevector v = new asn1encodablevector();
        for (int i = 0; i < atvs.length; i++)
        {
            v.add(atvs[i]);
        }
        content = new dersequence(v);
    }

    public attributetypeandvalue[] toattributetypeandvaluearray()
    {
        attributetypeandvalue[] result = new attributetypeandvalue[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = attributetypeandvalue.getinstance(content.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * controls  ::= sequence size(1..max) of attributetypeandvalue
     * </pre>
     *
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
