package org.ripple.bouncycastle.asn1.esf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * <pre>
 * crlocspref ::= sequence {
 *     crlids [0] crllistid optional,
 *     ocspids [1] ocsplistid optional,
 *     otherrev [2] otherrevrefs optional
 * }
 * </pre>
 */
public class crlocspref
    extends asn1object
{

    private crllistid crlids;
    private ocsplistid ocspids;
    private otherrevrefs otherrev;

    public static crlocspref getinstance(object obj)
    {
        if (obj instanceof crlocspref)
        {
            return (crlocspref)obj;
        }
        else if (obj != null)
        {
            return new crlocspref(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private crlocspref(asn1sequence seq)
    {
        enumeration e = seq.getobjects();
        while (e.hasmoreelements())
        {
            dertaggedobject o = (dertaggedobject)e.nextelement();
            switch (o.gettagno())
            {
                case 0:
                    this.crlids = crllistid.getinstance(o.getobject());
                    break;
                case 1:
                    this.ocspids = ocsplistid.getinstance(o.getobject());
                    break;
                case 2:
                    this.otherrev = otherrevrefs.getinstance(o.getobject());
                    break;
                default:
                    throw new illegalargumentexception("illegal tag");
            }
        }
    }

    public crlocspref(crllistid crlids, ocsplistid ocspids,
                      otherrevrefs otherrev)
    {
        this.crlids = crlids;
        this.ocspids = ocspids;
        this.otherrev = otherrev;
    }

    public crllistid getcrlids()
    {
        return this.crlids;
    }

    public ocsplistid getocspids()
    {
        return this.ocspids;
    }

    public otherrevrefs getotherrev()
    {
        return this.otherrev;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        if (null != this.crlids)
        {
            v.add(new dertaggedobject(true, 0, this.crlids.toasn1primitive()));
        }
        if (null != this.ocspids)
        {
            v.add(new dertaggedobject(true, 1, this.ocspids.toasn1primitive()));
        }
        if (null != this.otherrev)
        {
            v.add(new dertaggedobject(true, 2, this.otherrev.toasn1primitive()));
        }
        return new dersequence(v);
    }
}
