package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class genrepcontent
    extends asn1object
{
    private asn1sequence content;

    private genrepcontent(asn1sequence seq)
    {
        content = seq;
    }

    public static genrepcontent getinstance(object o)
    {
        if (o instanceof genrepcontent)
        {
            return (genrepcontent)o;
        }

        if (o != null)
        {
            return new genrepcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public genrepcontent(infotypeandvalue itv)
    {
        content = new dersequence(itv);
    }

    public genrepcontent(infotypeandvalue[] itv)
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
     * genrepcontent ::= sequence of infotypeandvalue
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
