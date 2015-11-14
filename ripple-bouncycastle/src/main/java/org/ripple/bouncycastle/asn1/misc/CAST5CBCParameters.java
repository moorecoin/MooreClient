package org.ripple.bouncycastle.asn1.misc;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class cast5cbcparameters
    extends asn1object
{
    asn1integer      keylength;
    asn1octetstring iv;

    public static cast5cbcparameters getinstance(
        object  o)
    {
        if (o instanceof cast5cbcparameters)
        {
            return (cast5cbcparameters)o;
        }
        else if (o != null)
        {
            return new cast5cbcparameters(asn1sequence.getinstance(o));
        }

        return null;
    }

    public cast5cbcparameters(
        byte[]  iv,
        int     keylength)
    {
        this.iv = new deroctetstring(iv);
        this.keylength = new asn1integer(keylength);
    }

    public cast5cbcparameters(
        asn1sequence  seq)
    {
        iv = (asn1octetstring)seq.getobjectat(0);
        keylength = (asn1integer)seq.getobjectat(1);
    }

    public byte[] getiv()
    {
        return iv.getoctets();
    }

    public int getkeylength()
    {
        return keylength.getvalue().intvalue();
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * cast5cbcparameters ::= sequence {
     *                           iv         octet string default 0,
     *                                  -- initialization vector
     *                           keylength  integer
     *                                  -- key length, in bits
     *                      }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(iv);
        v.add(keylength);

        return new dersequence(v);
    }
}
