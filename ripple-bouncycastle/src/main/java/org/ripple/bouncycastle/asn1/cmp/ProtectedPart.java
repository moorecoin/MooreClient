package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class protectedpart
    extends asn1object
{
    private pkiheader header;
    private pkibody body;

    private protectedpart(asn1sequence seq)
    {
        header = pkiheader.getinstance(seq.getobjectat(0));
        body = pkibody.getinstance(seq.getobjectat(1));
    }

    public static protectedpart getinstance(object o)
    {
        if (o instanceof protectedpart)
        {
            return (protectedpart)o;
        }

        if (o != null)
        {
            return new protectedpart(asn1sequence.getinstance(o));
        }

        return null;
    }

    public protectedpart(pkiheader header, pkibody body)
    {
        this.header = header;
        this.body = body;
    }

    public pkiheader getheader()
    {
        return header;
    }

    public pkibody getbody()
    {
        return body;
    }

    /**
     * <pre>
     * protectedpart ::= sequence {
     *                    header    pkiheader,
     *                    body      pkibody
     * }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(header);
        v.add(body);

        return new dersequence(v);
    }
}
