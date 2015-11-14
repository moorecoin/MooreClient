package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class otherkeyattribute
    extends asn1object
{
    private asn1objectidentifier keyattrid;
    private asn1encodable        keyattr;

    /**
     * return an otherkeyattribute object from the given object.
     *
     * @param o the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static otherkeyattribute getinstance(
        object o)
    {
        if (o == null || o instanceof otherkeyattribute)
        {
            return (otherkeyattribute)o;
        }
        
        if (o instanceof asn1sequence)
        {
            return new otherkeyattribute((asn1sequence)o);
        }

        throw new illegalargumentexception("unknown object in factory: " + o.getclass().getname());
    }
    
    public otherkeyattribute(
        asn1sequence seq)
    {
        keyattrid = (asn1objectidentifier)seq.getobjectat(0);
        keyattr = seq.getobjectat(1);
    }

    public otherkeyattribute(
        asn1objectidentifier keyattrid,
        asn1encodable        keyattr)
    {
        this.keyattrid = keyattrid;
        this.keyattr = keyattr;
    }

    public asn1objectidentifier getkeyattrid()
    {
        return keyattrid;
    }
    
    public asn1encodable getkeyattr()
    {
        return keyattr;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * otherkeyattribute ::= sequence {
     *     keyattrid object identifier,
     *     keyattr any defined by keyattrid optional
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(keyattrid);
        v.add(keyattr);

        return new dersequence(v);
    }
}
