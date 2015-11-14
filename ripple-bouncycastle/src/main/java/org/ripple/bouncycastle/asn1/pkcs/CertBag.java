package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class certbag
    extends asn1object
{
    private asn1objectidentifier certid;
    private asn1encodable certvalue;

    private certbag(
        asn1sequence    seq)
    {
        this.certid = (asn1objectidentifier)seq.getobjectat(0);
        this.certvalue = ((dertaggedobject)seq.getobjectat(1)).getobject();
    }

    public static certbag getinstance(object o)
    {
        if (o instanceof certbag)
        {
            return (certbag)o;
        }
        else if (o != null)
        {
            return new certbag(asn1sequence.getinstance(o));
        }

        return null;
    }

    public certbag(
        asn1objectidentifier certid,
        asn1encodable        certvalue)
    {
        this.certid = certid;
        this.certvalue = certvalue;
    }

    public asn1objectidentifier getcertid()
    {
        return certid;
    }

    public asn1encodable getcertvalue()
    {
        return certvalue;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(certid);
        v.add(new dertaggedobject(0, certvalue));

        return new dersequence(v);
    }
}
