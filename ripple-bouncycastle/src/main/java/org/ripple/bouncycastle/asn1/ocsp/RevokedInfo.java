package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derenumerated;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.crlreason;

public class revokedinfo
    extends asn1object
{
    private asn1generalizedtime  revocationtime;
    private crlreason           revocationreason;

    public revokedinfo(
        asn1generalizedtime  revocationtime,
        crlreason           revocationreason)
    {
        this.revocationtime = revocationtime;
        this.revocationreason = revocationreason;
    }

    private revokedinfo(
        asn1sequence    seq)
    {
        this.revocationtime = asn1generalizedtime.getinstance(seq.getobjectat(0));

        if (seq.size() > 1)
        {
            this.revocationreason = crlreason.getinstance(derenumerated.getinstance(
                                (asn1taggedobject)seq.getobjectat(1), true));
        }
    }

    public static revokedinfo getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static revokedinfo getinstance(
        object  obj)
    {
        if (obj instanceof revokedinfo)
        {
            return (revokedinfo)obj;
        }
        else if (obj != null)
        {
            return new revokedinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public asn1generalizedtime getrevocationtime()
    {
        return revocationtime;
    }

    public crlreason getrevocationreason()
    {
        return revocationreason;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * revokedinfo ::= sequence {
     *      revocationtime              generalizedtime,
     *      revocationreason    [0]     explicit crlreason optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(revocationtime);
        if (revocationreason != null)
        {
            v.add(new dertaggedobject(true, 0, revocationreason));
        }

        return new dersequence(v);
    }
}
