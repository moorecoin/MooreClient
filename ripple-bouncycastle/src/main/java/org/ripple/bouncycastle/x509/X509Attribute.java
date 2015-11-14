package org.ripple.bouncycastle.x509;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.derset;
import org.ripple.bouncycastle.asn1.x509.attribute;

/**
 * class for carrying the values in an x.509 attribute.
 */
public class x509attribute
    extends asn1object
{
    attribute    attr;
    
    /**
     * @param at an object representing an attribute.
     */
    x509attribute(
        asn1encodable   at)
    {
        this.attr = attribute.getinstance(at);
    }

    /**
     * create an x.509 attribute with the type given by the passed in oid and
     * the value represented by an asn.1 set containing value.
     * 
     * @param oid type of the attribute
     * @param value value object to go into the atribute's value set.
     */
    public x509attribute(
        string          oid,
        asn1encodable   value)
    {
        this.attr = new attribute(new asn1objectidentifier(oid), new derset(value));
    }
    
    /**
     * create an x.59 attribute with the type given by the passed in oid and the
     * value represented by an asn.1 set containing the objects in value.
     * 
     * @param oid type of the attribute
     * @param value vector of values to go in the attribute's value set.
     */
    public x509attribute(
        string              oid,
        asn1encodablevector value)
    {
        this.attr = new attribute(new asn1objectidentifier(oid), new derset(value));
    }
    
    public string getoid()
    {
        return attr.getattrtype().getid();
    }
    
    public asn1encodable[] getvalues()
    {
        asn1set         s = attr.getattrvalues();
        asn1encodable[] values = new asn1encodable[s.size()];
        
        for (int i = 0; i != s.size(); i++)
        {
            values[i] = (asn1encodable)s.getobjectat(i);
        }
        
        return values;
    }
    
    public asn1primitive toasn1primitive()
    {
        return attr.toasn1primitive();
    }
}
