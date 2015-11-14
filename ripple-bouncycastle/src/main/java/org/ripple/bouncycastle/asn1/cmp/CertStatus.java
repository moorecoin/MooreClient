package org.ripple.bouncycastle.asn1.cmp;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class certstatus
    extends asn1object
{
    private asn1octetstring certhash;
    private asn1integer certreqid;
    private pkistatusinfo statusinfo;

    private certstatus(asn1sequence seq)
    {
        certhash = asn1octetstring.getinstance(seq.getobjectat(0));
        certreqid = asn1integer.getinstance(seq.getobjectat(1));

        if (seq.size() > 2)
        {
            statusinfo = pkistatusinfo.getinstance(seq.getobjectat(2));
        }
    }

    public certstatus(byte[] certhash, biginteger certreqid)
    {
        this.certhash = new deroctetstring(certhash);
        this.certreqid = new asn1integer(certreqid);
    }

    public certstatus(byte[] certhash, biginteger certreqid, pkistatusinfo statusinfo)
    {
        this.certhash = new deroctetstring(certhash);
        this.certreqid = new asn1integer(certreqid);
        this.statusinfo = statusinfo;
    }

    public static certstatus getinstance(object o)
    {
        if (o instanceof certstatus)
        {
            return (certstatus)o;
        }

        if (o != null)
        {
            return new certstatus(asn1sequence.getinstance(o));
        }

        return null;
    }

    public asn1octetstring getcerthash()
    {
        return certhash;
    }

    public asn1integer getcertreqid()
    {
        return certreqid;
    }

    public pkistatusinfo getstatusinfo()
    {
        return statusinfo;
    }

    /**
     * <pre>
     * certstatus ::= sequence {
     *                   certhash    octet string,
     *                   -- the hash of the certificate, using the same hash algorithm
     *                   -- as is used to create and verify the certificate signature
     *                   certreqid   integer,
     *                   -- to match this confirmation with the corresponding req/rep
     *                   statusinfo  pkistatusinfo optional
     * }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certhash);
        v.add(certreqid);

        if (statusinfo != null)
        {
            v.add(statusinfo);
        }

        return new dersequence(v);
    }
}
