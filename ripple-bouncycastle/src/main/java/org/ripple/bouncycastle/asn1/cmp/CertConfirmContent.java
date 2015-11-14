package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;

public class certconfirmcontent
    extends asn1object
{
    private asn1sequence content;

    private certconfirmcontent(asn1sequence seq)
    {
        content = seq;
    }

    public static certconfirmcontent getinstance(object o)
    {
        if (o instanceof certconfirmcontent)
        {
            return (certconfirmcontent)o;
        }

        if (o != null)
        {
            return new certconfirmcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public certstatus[] tocertstatusarray()
    {
        certstatus[] result = new certstatus[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = certstatus.getinstance(content.getobjectat(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * certconfirmcontent ::= sequence of certstatus
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
