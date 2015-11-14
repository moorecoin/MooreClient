package org.ripple.bouncycastle.asn1.pkcs;

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
    private asn1set              attrvalues;

    /**
     * return an attribute object from the given object.
     *
     * @param o the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static attribute getinstance(
        object o)
    {
        if (o == null || o instanceof attribute)
        {
            return (attribute)o;
        }
        
        if (o instanceof asn1sequence)
        {
            return new attribute((asn1sequence)o);
        }

        throw new illegalargumentexception("unknown object in factory: " + o.getclass().getname());
    }
    
    public attribute(
        asn1sequence seq)
    {
        attrtype = (asn1objectidentifier)seq.getobjectat(0);
        attrvalues = (asn1set)seq.getobjectat(1);
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
        return attrtype;
    }
    
    public asn1set getattrvalues()
    {
        return attrvalues;
    }

    public asn1encodable[] getattributevalues()
    {
        return attrvalues.toarray();
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
