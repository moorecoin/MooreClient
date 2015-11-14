package org.ripple.bouncycastle.asn1.esf;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * <pre>
 * otherrevvals ::= sequence {
 *    otherrevvaltype otherrevvaltype,
 *    otherrevvals any defined by otherrevvaltype
 * }
 *
 * otherrevvaltype ::= object identifier
 * </pre>
 */
public class otherrevvals
    extends asn1object
{

    private asn1objectidentifier otherrevvaltype;

    private asn1encodable otherrevvals;

    public static otherrevvals getinstance(object obj)
    {
        if (obj instanceof otherrevvals)
        {
            return (otherrevvals)obj;
        }
        if (obj != null)
        {
            return new otherrevvals(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private otherrevvals(asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        this.otherrevvaltype = (asn1objectidentifier)seq.getobjectat(0);
        try
        {
            this.otherrevvals = asn1primitive.frombytearray(seq.getobjectat(1)
                .toasn1primitive().getencoded(asn1encoding.der));
        }
        catch (ioexception e)
        {
            throw new illegalstateexception();
        }
    }

    public otherrevvals(asn1objectidentifier otherrevvaltype,
                        asn1encodable otherrevvals)
    {
        this.otherrevvaltype = otherrevvaltype;
        this.otherrevvals = otherrevvals;
    }

    public asn1objectidentifier getotherrevvaltype()
    {
        return this.otherrevvaltype;
    }

    public asn1encodable getotherrevvals()
    {
        return this.otherrevvals;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(this.otherrevvaltype);
        v.add(this.otherrevvals);
        return new dersequence(v);
    }
}
