package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.bertaggedobject;

public class encrypteddata
    extends asn1object
{
    private asn1integer version;
    private encryptedcontentinfo encryptedcontentinfo;
    private asn1set unprotectedattrs;

    public static encrypteddata getinstance(object o)
    {
        if (o instanceof encrypteddata)
        {
            return (encrypteddata)o;
        }

        if (o != null)
        {
            return new encrypteddata(asn1sequence.getinstance(o));
        }

        return null;
    }

    public encrypteddata(encryptedcontentinfo encinfo)
    {
        this(encinfo,  null);
    }

    public encrypteddata(encryptedcontentinfo encinfo, asn1set unprotectedattrs)
    {
        this.version = new asn1integer((unprotectedattrs == null) ? 0 : 2);
        this.encryptedcontentinfo = encinfo;
        this.unprotectedattrs = unprotectedattrs;
    }

    private encrypteddata(asn1sequence seq)
    {
        this.version = asn1integer.getinstance(seq.getobjectat(0));
        this.encryptedcontentinfo = encryptedcontentinfo.getinstance(seq.getobjectat(1));

        if (seq.size() == 3)
        {
            this.unprotectedattrs = asn1set.getinstance(seq.getobjectat(2));
        }
    }

    public asn1integer getversion()
    {
        return version;
    }

    public encryptedcontentinfo getencryptedcontentinfo()
    {
        return encryptedcontentinfo;
    }

    public asn1set getunprotectedattrs()
    {
        return unprotectedattrs;
    }

    /**
     * <pre>
     *       encrypteddata ::= sequence {
     *                     version cmsversion,
     *                     encryptedcontentinfo encryptedcontentinfo,
     *                     unprotectedattrs [1] implicit unprotectedattributes optional }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(version);
        v.add(encryptedcontentinfo);
        if (unprotectedattrs != null)
        {
            v.add(new bertaggedobject(false, 1, unprotectedattrs));
        }

        return new bersequence(v);
    }
}
