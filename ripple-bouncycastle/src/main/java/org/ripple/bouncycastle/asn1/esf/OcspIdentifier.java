package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.ocsp.responderid;

/**
 * <pre>
 * ocspidentifier ::= sequence {
 *     ocspresponderid responderid, -- as in ocsp response data
 *     producedat generalizedtime -- as in ocsp response data
 * }
 * </pre>
 */
public class ocspidentifier
    extends asn1object
{
    private responderid ocspresponderid;
    private asn1generalizedtime producedat;

    public static ocspidentifier getinstance(object obj)
    {
        if (obj instanceof ocspidentifier)
        {
            return (ocspidentifier)obj;
        }
        else if (obj != null)
        {
            return new ocspidentifier(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private ocspidentifier(asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        this.ocspresponderid = responderid.getinstance(seq.getobjectat(0));
        this.producedat = (asn1generalizedtime)seq.getobjectat(1);
    }

    public ocspidentifier(responderid ocspresponderid, asn1generalizedtime producedat)
    {
        this.ocspresponderid = ocspresponderid;
        this.producedat = producedat;
    }

    public responderid getocspresponderid()
    {
        return this.ocspresponderid;
    }

    public asn1generalizedtime getproducedat()
    {
        return this.producedat;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(this.ocspresponderid);
        v.add(this.producedat);
        return new dersequence(v);
    }
}
