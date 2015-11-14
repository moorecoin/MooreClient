package org.ripple.bouncycastle.asn1.cmp;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class errormsgcontent
    extends asn1object
{
    private pkistatusinfo pkistatusinfo;
    private asn1integer errorcode;
    private pkifreetext errordetails;

    private errormsgcontent(asn1sequence seq)
    {
        enumeration en = seq.getobjects();

        pkistatusinfo = pkistatusinfo.getinstance(en.nextelement());

        while (en.hasmoreelements())
        {
            object o = en.nextelement();

            if (o instanceof asn1integer)
            {
                errorcode = asn1integer.getinstance(o);
            }
            else
            {
                errordetails = pkifreetext.getinstance(o);
            }
        }
    }

    public static errormsgcontent getinstance(object o)
    {
        if (o instanceof errormsgcontent)
        {
            return (errormsgcontent)o;
        }

        if (o != null)
        {
            return new errormsgcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public errormsgcontent(pkistatusinfo pkistatusinfo)
    {
        this(pkistatusinfo, null, null);
    }

    public errormsgcontent(
        pkistatusinfo pkistatusinfo,
        asn1integer errorcode,
        pkifreetext errordetails)
    {
        if (pkistatusinfo == null)
        {
            throw new illegalargumentexception("'pkistatusinfo' cannot be null");
        }

        this.pkistatusinfo = pkistatusinfo;
        this.errorcode = errorcode;
        this.errordetails = errordetails;
    }

    public pkistatusinfo getpkistatusinfo()
    {
        return pkistatusinfo;
    }

    public asn1integer geterrorcode()
    {
        return errorcode;
    }

    public pkifreetext geterrordetails()
    {
        return errordetails;
    }

    /**
     * <pre>
     * errormsgcontent ::= sequence {
     *                        pkistatusinfo          pkistatusinfo,
     *                        errorcode              integer           optional,
     *                        -- implementation-specific error codes
     *                        errordetails           pkifreetext       optional
     *                        -- implementation-specific error details
     * }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(pkistatusinfo);
        addoptional(v, errorcode);
        addoptional(v, errordetails);

        return new dersequence(v);
    }

    private void addoptional(asn1encodablevector v, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(obj);
        }
    }
}
