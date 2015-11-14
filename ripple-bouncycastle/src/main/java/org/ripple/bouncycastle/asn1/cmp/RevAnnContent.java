package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.crmf.certid;
import org.ripple.bouncycastle.asn1.x509.extensions;

public class revanncontent
    extends asn1object
{
    private pkistatus status;
    private certid certid;
    private asn1generalizedtime willberevokedat;
    private asn1generalizedtime badsincedate;
    private extensions crldetails;
    
    private revanncontent(asn1sequence seq)
    {
        status = pkistatus.getinstance(seq.getobjectat(0));
        certid = certid.getinstance(seq.getobjectat(1));
        willberevokedat = asn1generalizedtime.getinstance(seq.getobjectat(2));
        badsincedate = asn1generalizedtime.getinstance(seq.getobjectat(3));

        if (seq.size() > 4)
        {
            crldetails = extensions.getinstance(seq.getobjectat(4));
        }
    }

    public static revanncontent getinstance(object o)
    {
        if (o instanceof revanncontent)
        {
            return (revanncontent)o;
        }

        if (o != null)
        {
            return new revanncontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public pkistatus getstatus()
    {
        return status;
    }

    public certid getcertid()
    {
        return certid;
    }

    public asn1generalizedtime getwillberevokedat()
    {
        return willberevokedat;
    }

    public asn1generalizedtime getbadsincedate()
    {
        return badsincedate;
    }

    public extensions getcrldetails()
    {
        return crldetails;
    }

    /**
     * <pre>
     * revanncontent ::= sequence {
     *       status              pkistatus,
     *       certid              certid,
     *       willberevokedat     generalizedtime,
     *       badsincedate        generalizedtime,
     *       crldetails          extensions  optional
     *        -- extra crl details (e.g., crl number, reason, location, etc.)
     * }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(status);
        v.add(certid);
        v.add(willberevokedat);
        v.add(badsincedate);

        if (crldetails != null)
        {
            v.add(crldetails);
        }

        return new dersequence(v);
    }
}
