package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;

public class popodeckeychallcontent
    extends asn1object
{
    private asn1sequence content;

    private popodeckeychallcontent(asn1sequence seq)
    {
        content = seq;
    }

    public static popodeckeychallcontent getinstance(object o)
    {
        if (o instanceof popodeckeychallcontent)
        {
            return (popodeckeychallcontent)o;
        }

        if (o != null)
        {
            return new popodeckeychallcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public challenge[] tochallengearray()
    {
        challenge[] result = new challenge[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = challenge.getinstance(content.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * popodeckeychallcontent ::= sequence of challenge
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
