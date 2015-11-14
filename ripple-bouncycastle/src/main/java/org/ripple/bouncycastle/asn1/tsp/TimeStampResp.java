package org.ripple.bouncycastle.asn1.tsp;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.cmp.pkistatusinfo;
import org.ripple.bouncycastle.asn1.cms.contentinfo;


public class timestampresp
    extends asn1object
{
    pkistatusinfo pkistatusinfo;

    contentinfo timestamptoken;

    public static timestampresp getinstance(object o)
    {
        if (o instanceof timestampresp)
        {
            return (timestampresp) o;
        }
        else if (o != null)
        {
            return new timestampresp(asn1sequence.getinstance(o));
        }

        return null;
    }

    private timestampresp(asn1sequence seq)
    {

        enumeration e = seq.getobjects();

        // status
        pkistatusinfo = pkistatusinfo.getinstance(e.nextelement());

        if (e.hasmoreelements())
        {
            timestamptoken = contentinfo.getinstance(e.nextelement());
        }
    }

    public timestampresp(pkistatusinfo pkistatusinfo, contentinfo timestamptoken)
    {
        this.pkistatusinfo = pkistatusinfo;
        this.timestamptoken = timestamptoken;
    }

    public pkistatusinfo getstatus()
    {
        return pkistatusinfo;
    }

    public contentinfo gettimestamptoken()
    {
        return timestamptoken;
    }

    /**
     * <pre>
     * timestampresp ::= sequence  {
     *   status                  pkistatusinfo,
     *   timestamptoken          timestamptoken     optional  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        
        v.add(pkistatusinfo);
        if (timestamptoken != null)
        {
            v.add(timestamptoken);
        }

        return new dersequence(v);
    }
}
