package org.ripple.bouncycastle.asn1.eac;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class unsignedinteger
    extends asn1object
{
    private int tagno;
    private biginteger value;

    public unsignedinteger(int tagno, biginteger value)
    {
        this.tagno = tagno;
        this.value = value;
    }

    private unsignedinteger(asn1taggedobject obj)
    {
        this.tagno = obj.gettagno();
        this.value = new biginteger(1, asn1octetstring.getinstance(obj, false).getoctets());
    }

    public static unsignedinteger getinstance(object obj)
    {
        if (obj instanceof  unsignedinteger)
        {
            return (unsignedinteger)obj;
        }
        if (obj != null)
        {
            return new unsignedinteger(asn1taggedobject.getinstance(obj));
        }

        return null;
    }

    private byte[] convertvalue()
    {
        byte[] v = value.tobytearray();

        if (v[0] == 0)
        {
            byte[] tmp = new byte[v.length - 1];

            system.arraycopy(v, 1, tmp, 0, tmp.length);

            return tmp;
        }

        return v;
    }

    public int gettagno()
    {
        return tagno;
    }

    public biginteger getvalue()
    {
        return value;
    }

    public asn1primitive toasn1primitive()
    {
        return new dertaggedobject(false, tagno, new deroctetstring(convertvalue()));
    }
}
