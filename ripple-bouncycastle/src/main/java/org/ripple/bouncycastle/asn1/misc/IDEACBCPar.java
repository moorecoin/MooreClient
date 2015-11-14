package org.ripple.bouncycastle.asn1.misc;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class ideacbcpar
    extends asn1object
{
    asn1octetstring  iv;

    public static ideacbcpar getinstance(
        object  o)
    {
        if (o instanceof ideacbcpar)
        {
            return (ideacbcpar)o;
        }
        else if (o != null)
        {
            return new ideacbcpar(asn1sequence.getinstance(o));
        }

        return null;
    }

    public ideacbcpar(
        byte[]  iv)
    {
        this.iv = new deroctetstring(iv);
    }

    public ideacbcpar(
        asn1sequence  seq)
    {
        if (seq.size() == 1)
        {
            iv = (asn1octetstring)seq.getobjectat(0);
        }
        else
        {
            iv = null;
        }
    }

    public byte[] getiv()
    {
        if (iv != null)
        {
            return iv.getoctets();
        }
        else
        {
            return null;
        }
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * idea-cbcpar ::= sequence {
     *                      iv    octet string optional -- exactly 8 octets
     *                  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        if (iv != null)
        {
            v.add(iv);
        }

        return new dersequence(v);
    }
}
