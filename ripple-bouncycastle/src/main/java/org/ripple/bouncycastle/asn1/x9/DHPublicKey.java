package org.ripple.bouncycastle.asn1.x9;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;

public class dhpublickey
    extends asn1object
{
    private asn1integer y;

    public static dhpublickey getinstance(asn1taggedobject obj, boolean explicit)
    {
        return getinstance(asn1integer.getinstance(obj, explicit));
    }

    public static dhpublickey getinstance(object obj)
    {
        if (obj == null || obj instanceof dhpublickey)
        {
            return (dhpublickey)obj;
        }

        if (obj instanceof asn1integer)
        {
            return new dhpublickey((asn1integer)obj);
        }

        throw new illegalargumentexception("invalid dhpublickey: " + obj.getclass().getname());
    }

    public dhpublickey(asn1integer y)
    {
        if (y == null)
        {
            throw new illegalargumentexception("'y' cannot be null");
        }

        this.y = y;
    }

    public asn1integer gety()
    {
        return this.y;
    }

    public asn1primitive toasn1primitive()
    {
        return this.y;
    }
}
