package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.dersequence;

public class attribute
    extends asn1object
{
    private asn1objectidentifier attrtype;
    private asn1set             attrvalues;

    /**
     * return an attribute object from the given object.
     *
     * @param o the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static attribute getinstance(
        object o)
    {
        if (o instanceof attribute)
        {
            return (attribute)o;
        }
        
        if (o != null)
        {
            return new attribute(asn1sequence.getinstance(o));
        }

        return null;
    }
    
    private attribute(
        asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        attrtype = asn1objectidentifier.getinstance(seq.getobjectat(0));
        attrvalues = asn1set.getinstance(seq.getobjectat(1));
    }

    public attribute(
        asn1objectidentifier attrtype,
        asn1set             attrvalues)
    {
        this.attrtype = attrtype;
        this.attrvalues = attrvalues;
    }

    public asn1objectidentifier getattrtype()
    {
        return new asn1objectidentifier(attrtype.getid());
    }

    public asn1encodable[] getattributevalues()
    {
        return attrvalues.toarray();
    }

    public asn1set getattrvalues()
    {
        return attrvalues;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * attribute ::= sequence {
     *     attrtype object identifier,
     *     attrvalues set of attributevalue
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(attrtype);
        v.add(attrvalues);

        return new dersequence(v);
    }
}
