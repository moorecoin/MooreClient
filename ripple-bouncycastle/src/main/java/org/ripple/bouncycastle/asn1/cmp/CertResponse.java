package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class certresponse
    extends asn1object
{
    private asn1integer certreqid;
    private pkistatusinfo status;
    private certifiedkeypair certifiedkeypair;
    private asn1octetstring rspinfo;

    private certresponse(asn1sequence seq)
    {
        certreqid = asn1integer.getinstance(seq.getobjectat(0));
        status = pkistatusinfo.getinstance(seq.getobjectat(1));

        if (seq.size() >= 3)
        {
            if (seq.size() == 3)
            {
                asn1encodable o = seq.getobjectat(2);
                if (o instanceof asn1octetstring)
                {
                    rspinfo = asn1octetstring.getinstance(o);
                }
                else
                {
                    certifiedkeypair = certifiedkeypair.getinstance(o);
                }
            }
            else
            {
                certifiedkeypair = certifiedkeypair.getinstance(seq.getobjectat(2));
                rspinfo = asn1octetstring.getinstance(seq.getobjectat(3));
            }
        }
    }

    public static certresponse getinstance(object o)
    {
        if (o instanceof certresponse)
        {
            return (certresponse)o;
        }

        if (o != null)
        {
            return new certresponse(asn1sequence.getinstance(o));
        }

        return null;
    }

    public certresponse(
        asn1integer certreqid,
        pkistatusinfo status)
    {
        this(certreqid, status, null, null);
    }

    public certresponse(
        asn1integer certreqid,
        pkistatusinfo status,
        certifiedkeypair certifiedkeypair,
        asn1octetstring rspinfo)
    {
        if (certreqid == null)
        {
            throw new illegalargumentexception("'certreqid' cannot be null");
        }
        if (status == null)
        {
            throw new illegalargumentexception("'status' cannot be null");
        }
        this.certreqid = certreqid;
        this.status = status;
        this.certifiedkeypair = certifiedkeypair;
        this.rspinfo = rspinfo;
    }

    public asn1integer getcertreqid()
    {
        return certreqid;
    }

    public pkistatusinfo getstatus()
    {
        return status;
    }

    public certifiedkeypair getcertifiedkeypair()
    {
        return certifiedkeypair;
    }

    /**
     * <pre>
     * certresponse ::= sequence {
     *                            certreqid           integer,
     *                            -- to match this response with corresponding request (a value
     *                            -- of -1 is to be used if certreqid is not specified in the
     *                            -- corresponding request)
     *                            status              pkistatusinfo,
     *                            certifiedkeypair    certifiedkeypair    optional,
     *                            rspinfo             octet string        optional
     *                            -- analogous to the id-reginfo-utf8pairs string defined
     *                            -- for reginfo in certreqmsg [crmf]
     *             }
     * </pre> 
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certreqid);
        v.add(status);

        if (certifiedkeypair != null)
        {
            v.add(certifiedkeypair);
        }

        if (rspinfo != null)
        {
            v.add(rspinfo);
        }
        
        return new dersequence(v);
    }
}
