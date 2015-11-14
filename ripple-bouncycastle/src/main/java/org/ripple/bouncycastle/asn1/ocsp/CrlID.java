package org.ripple.bouncycastle.asn1.ocsp;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class crlid
    extends asn1object
{
    private deria5string         crlurl;
    private asn1integer          crlnum;
    private asn1generalizedtime  crltime;

    private crlid(
        asn1sequence    seq)
    {
        enumeration    e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1taggedobject    o = (asn1taggedobject)e.nextelement();

            switch (o.gettagno())
            {
            case 0:
                crlurl = deria5string.getinstance(o, true);
                break;
            case 1:
                crlnum = asn1integer.getinstance(o, true);
                break;
            case 2:
                crltime = dergeneralizedtime.getinstance(o, true);
                break;
            default:
                throw new illegalargumentexception(
                        "unknown tag number: " + o.gettagno());
            }
        }
    }

    public static crlid getinstance(
        object  obj)
    {
        if (obj instanceof crlid)
        {
            return (crlid)obj;
        }
        else if (obj != null)
        {
            return new crlid(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public deria5string getcrlurl()
    {
        return crlurl;
    }

    public asn1integer getcrlnum()
    {
        return crlnum;
    }

    public asn1generalizedtime getcrltime()
    {
        return crltime;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * crlid ::= sequence {
     *     crlurl               [0]     explicit ia5string optional,
     *     crlnum               [1]     explicit integer optional,
     *     crltime              [2]     explicit generalizedtime optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        if (crlurl != null)
        {
            v.add(new dertaggedobject(true, 0, crlurl));
        }

        if (crlnum != null)
        {
            v.add(new dertaggedobject(true, 1, crlnum));
        }

        if (crltime != null)
        {
            v.add(new dertaggedobject(true, 2, crltime));
        }

        return new dersequence(v);
    }
}
