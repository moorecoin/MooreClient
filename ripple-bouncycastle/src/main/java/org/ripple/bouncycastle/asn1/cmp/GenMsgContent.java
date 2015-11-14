package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class genmsgcontent
    extends asn1object
{
    private asn1sequence content;

    private genmsgcontent(asn1sequence seq)
    {
        content = seq;
    }

    public static genmsgcontent getinstance(object o)
    {
        if (o instanceof genmsgcontent)
        {
            return (genmsgcontent)o;
        }

        if (o != null)
        {
            return new genmsgcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public genmsgcontent(infotypeandvalue itv)
    {
        content = new dersequence(itv);
    }

    public genmsgcontent(infotypeandvalue[] itv)
    {
        asn1encodablevector v = new asn1encodablevector();
        for (int i = 0; i < itv.length; i++)
        {
            v.add(itv[i]);
        }
        content = new dersequence(v);
    }

    public infotypeandvalue[] toinfotypeandvaluearray()
    {
        infotypeandvalue[] result = new infotypeandvalue[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = infotypeandvalue.getinstance(content.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * genmsgcontent ::= sequence of infotypeandvalue
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
