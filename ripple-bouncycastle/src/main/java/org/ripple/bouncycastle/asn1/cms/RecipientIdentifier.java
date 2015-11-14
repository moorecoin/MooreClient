package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class recipientidentifier
    extends asn1object
    implements asn1choice
{
    private asn1encodable id;
    
    public recipientidentifier(
        issuerandserialnumber id)
    {
        this.id = id;
    }
    
    public recipientidentifier(
        asn1octetstring id)
    {
        this.id = new dertaggedobject(false, 0, id);
    }
    
    public recipientidentifier(
        asn1primitive id)
    {
        this.id = id;
    }
    
    /**
     * return a recipientidentifier object from the given object.
     *
     * @param o the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static recipientidentifier getinstance(
        object o)
    {
        if (o == null || o instanceof recipientidentifier)
        {
            return (recipientidentifier)o;
        }
        
        if (o instanceof issuerandserialnumber)
        {
            return new recipientidentifier((issuerandserialnumber)o);
        }
        
        if (o instanceof asn1octetstring)
        {
            return new recipientidentifier((asn1octetstring)o);
        }
        
        if (o instanceof asn1primitive)
        {
            return new recipientidentifier((asn1primitive)o);
        }
        
        throw new illegalargumentexception(
          "illegal object in recipientidentifier: " + o.getclass().getname());
    } 

    public boolean istagged()
    {
        return (id instanceof asn1taggedobject);
    }

    public asn1encodable getid()
    {
        if (id instanceof asn1taggedobject)
        {
            return asn1octetstring.getinstance((asn1taggedobject)id, false);
        }

        return issuerandserialnumber.getinstance(id);
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * recipientidentifier ::= choice {
     *     issuerandserialnumber issuerandserialnumber,
     *     subjectkeyidentifier [0] subjectkeyidentifier 
     * }
     *
     * subjectkeyidentifier ::= octet string
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return id.toasn1primitive();
    }
}
