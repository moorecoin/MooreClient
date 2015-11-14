package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class ocsprequest
    extends asn1object
{
    tbsrequest      tbsrequest;
    signature       optionalsignature;

    public ocsprequest(
        tbsrequest  tbsrequest,
        signature   optionalsignature)
    {
        this.tbsrequest = tbsrequest;
        this.optionalsignature = optionalsignature;
    }

    private ocsprequest(
        asn1sequence    seq)
    {
        tbsrequest = tbsrequest.getinstance(seq.getobjectat(0));

        if (seq.size() == 2)
        {
            optionalsignature = signature.getinstance(
                                (asn1taggedobject)seq.getobjectat(1), true);
        }
    }
    
    public static ocsprequest getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static ocsprequest getinstance(
        object  obj)
    {
        if (obj instanceof ocsprequest)
        {
            return (ocsprequest)obj;
        }
        else if (obj != null)
        {
            return new ocsprequest(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    public tbsrequest gettbsrequest()
    {
        return tbsrequest;
    }

    public signature getoptionalsignature()
    {
        return optionalsignature;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * ocsprequest     ::=     sequence {
     *     tbsrequest                  tbsrequest,
     *     optionalsignature   [0]     explicit signature optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(tbsrequest);

        if (optionalsignature != null)
        {
            v.add(new dertaggedobject(true, 0, optionalsignature));
        }

        return new dersequence(v);
    }
}
