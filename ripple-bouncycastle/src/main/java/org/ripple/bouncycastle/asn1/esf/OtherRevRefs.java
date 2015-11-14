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
 * otherrevrefs ::= sequence {
 *   otherrevreftype otherrevreftype,
 *   otherrevrefs any defined by otherrevreftype
 * }
 *
 * otherrevreftype ::= object identifier
 * </pre>
 */
public class otherrevrefs
    extends asn1object
{

    private asn1objectidentifier otherrevreftype;
    private asn1encodable otherrevrefs;

    public static otherrevrefs getinstance(object obj)
    {
        if (obj instanceof otherrevrefs)
        {
            return (otherrevrefs)obj;
        }
        else if (obj != null)
        {
            return new otherrevrefs(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private otherrevrefs(asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        this.otherrevreftype = new asn1objectidentifier(((asn1objectidentifier)seq.getobjectat(0)).getid());
        try
        {
            this.otherrevrefs = asn1primitive.frombytearray(seq.getobjectat(1)
                .toasn1primitive().getencoded(asn1encoding.der));
        }
        catch (ioexception e)
        {
            throw new illegalstateexception();
        }
    }

    public otherrevrefs(asn1objectidentifier otherrevreftype, asn1encodable otherrevrefs)
    {
        this.otherrevreftype = otherrevreftype;
        this.otherrevrefs = otherrevrefs;
    }

    public asn1objectidentifier getotherrevreftype()
    {
        return this.otherrevreftype;
    }

    public asn1encodable getotherrevrefs()
    {
        return this.otherrevrefs;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(this.otherrevreftype);
        v.add(this.otherrevrefs);
        return new dersequence(v);
    }
}
