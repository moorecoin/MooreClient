package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1null;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.dernull;

public class pkiconfirmcontent
    extends asn1object
{
    private asn1null val;

    private pkiconfirmcontent(asn1null val)
    {
        this.val = val;
    }

    public static pkiconfirmcontent getinstance(object o)
    {
        if (o == null || o instanceof pkiconfirmcontent)
        {
            return (pkiconfirmcontent)o;
        }

        if (o instanceof asn1null)
        {
            return new pkiconfirmcontent((asn1null)o);
        }

        throw new illegalargumentexception("invalid object: " + o.getclass().getname());
    }

    public pkiconfirmcontent()
    {
        val = dernull.instance;
    }

    /**
     * <pre>
     * pkiconfirmcontent ::= null
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return val;
    }
}
