package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class attributetypeandvalue
    extends asn1object
{
    private asn1objectidentifier type;
    private asn1encodable       value;

    private attributetypeandvalue(asn1sequence seq)
    {
        type = (asn1objectidentifier)seq.getobjectat(0);
        value = (asn1encodable)seq.getobjectat(1);
    }

    public static attributetypeandvalue getinstance(object o)
    {
        if (o instanceof attributetypeandvalue)
        {
            return (attributetypeandvalue)o;
        }

        if (o != null)
        {
            return new attributetypeandvalue(asn1sequence.getinstance(o));
        }

        return null;
    }

    public attributetypeandvalue(
        string oid,
        asn1encodable value)
    {
        this(new asn1objectidentifier(oid), value);
    }

    public attributetypeandvalue(
        asn1objectidentifier type,
        asn1encodable value)
    {
        this.type = type;
        this.value = value;
    }

    public asn1objectidentifier gettype()
    {
        return type;
    }

    public asn1encodable getvalue()
    {
        return value;
    }

    /**
     * <pre>
     * attributetypeandvalue ::= sequence {
     *           type         object identifier,
     *           value        any defined by type }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(type);
        v.add(value);

        return new dersequence(v);
    }
}
