package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class revreqcontent
    extends asn1object
{
    private asn1sequence content;

    private revreqcontent(asn1sequence seq)
    {
        content = seq;
    }

    public static revreqcontent getinstance(object o)
    {
        if (o instanceof revreqcontent)
        {
            return (revreqcontent)o;
        }

        if (o != null)
        {
            return new revreqcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public revreqcontent(revdetails revdetails)
    {
        this.content = new dersequence(revdetails);
    }

    public revreqcontent(revdetails[] revdetailsarray)
    {
        asn1encodablevector v = new asn1encodablevector();

        for (int i = 0; i != revdetailsarray.length; i++)
        {
            v.add(revdetailsarray[i]);
        }

        this.content = new dersequence(v);
    }

    public revdetails[] torevdetailsarray()
    {
        revdetails[] result = new revdetails[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = revdetails.getinstance(content.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * revreqcontent ::= sequence of revdetails
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
