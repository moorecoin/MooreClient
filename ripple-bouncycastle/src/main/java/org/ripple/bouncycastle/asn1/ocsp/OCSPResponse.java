package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class ocspresponse
    extends asn1object
{
    ocspresponsestatus    responsestatus;
    responsebytes        responsebytes;

    public ocspresponse(
        ocspresponsestatus  responsestatus,
        responsebytes       responsebytes)
    {
        this.responsestatus = responsestatus;
        this.responsebytes = responsebytes;
    }

    private ocspresponse(
        asn1sequence    seq)
    {
        responsestatus = ocspresponsestatus.getinstance(seq.getobjectat(0));

        if (seq.size() == 2)
        {
            responsebytes = responsebytes.getinstance(
                                (asn1taggedobject)seq.getobjectat(1), true);
        }
    }

    public static ocspresponse getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static ocspresponse getinstance(
        object  obj)
    {
        if (obj instanceof ocspresponse)
        {
            return (ocspresponse)obj;
        }
        else if (obj != null)
        {
            return new ocspresponse(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public ocspresponsestatus getresponsestatus()
    {
        return responsestatus;
    }

    public responsebytes getresponsebytes()
    {
        return responsebytes;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * ocspresponse ::= sequence {
     *     responsestatus         ocspresponsestatus,
     *     responsebytes          [0] explicit responsebytes optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(responsestatus);

        if (responsebytes != null)
        {
            v.add(new dertaggedobject(true, 0, responsebytes));
        }

        return new dersequence(v);
    }
}
