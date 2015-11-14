package org.ripple.bouncycastle.asn1.pkcs;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.bersequence;

/**
 * the infamous pfx from pkcs12
 */
public class pfx
    extends asn1object
    implements pkcsobjectidentifiers
{
    private contentinfo             contentinfo;
    private macdata                 macdata = null;

    private pfx(
        asn1sequence   seq)
    {
        biginteger  version = ((asn1integer)seq.getobjectat(0)).getvalue();
        if (version.intvalue() != 3)
        {
            throw new illegalargumentexception("wrong version for pfx pdu");
        }

        contentinfo = contentinfo.getinstance(seq.getobjectat(1));

        if (seq.size() == 3)
        {
            macdata = macdata.getinstance(seq.getobjectat(2));
        }
    }

    public static pfx getinstance(
        object  obj)
    {
        if (obj instanceof pfx)
        {
            return (pfx)obj;
        }

        if (obj != null)
        {
            return new pfx(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public pfx(
        contentinfo     contentinfo,
        macdata         macdata)
    {
        this.contentinfo = contentinfo;
        this.macdata = macdata;
    }

    public contentinfo getauthsafe()
    {
        return contentinfo;
    }

    public macdata getmacdata()
    {
        return macdata;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(new asn1integer(3));
        v.add(contentinfo);

        if (macdata != null)
        {
            v.add(macdata);
        }

        return new bersequence(v);
    }
}
