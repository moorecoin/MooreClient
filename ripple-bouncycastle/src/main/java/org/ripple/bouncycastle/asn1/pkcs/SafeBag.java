package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dlsequence;
import org.ripple.bouncycastle.asn1.dltaggedobject;

public class safebag
    extends asn1object
{
    private asn1objectidentifier bagid;
    private asn1encodable bagvalue;
    private asn1set                     bagattributes;

    public safebag(
        asn1objectidentifier oid,
        asn1encodable obj)
    {
        this.bagid = oid;
        this.bagvalue = obj;
        this.bagattributes = null;
    }

    public safebag(
        asn1objectidentifier oid,
        asn1encodable obj,
        asn1set                 bagattributes)
    {
        this.bagid = oid;
        this.bagvalue = obj;
        this.bagattributes = bagattributes;
    }

    public static safebag getinstance(
        object  obj)
    {
        if (obj instanceof safebag)
        {
            return (safebag)obj;
        }

        if (obj != null)
        {
            return new safebag(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private safebag(
        asn1sequence    seq)
    {
        this.bagid = (asn1objectidentifier)seq.getobjectat(0);
        this.bagvalue = ((asn1taggedobject)seq.getobjectat(1)).getobject();
        if (seq.size() == 3)
        {
            this.bagattributes = (asn1set)seq.getobjectat(2);
        }
    }

    public asn1objectidentifier getbagid()
    {
        return bagid;
    }

    public asn1encodable getbagvalue()
    {
        return bagvalue;
    }

    public asn1set getbagattributes()
    {
        return bagattributes;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(bagid);
        v.add(new dltaggedobject(true, 0, bagvalue));

        if (bagattributes != null)
        {
            v.add(bagattributes);
        }

        return new dlsequence(v);
    }
}
