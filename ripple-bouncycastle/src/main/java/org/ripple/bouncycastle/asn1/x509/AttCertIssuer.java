package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class attcertissuer
    extends asn1object
    implements asn1choice
{
    asn1encodable   obj;
    asn1primitive choiceobj;
    
    public static attcertissuer getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof attcertissuer)
        {
            return (attcertissuer)obj;
        }
        else if (obj instanceof v2form)
        {
            return new attcertissuer(v2form.getinstance(obj));
        }
        else if (obj instanceof generalnames)
        {
            return new attcertissuer((generalnames)obj);
        }
        else if (obj instanceof asn1taggedobject)
        {
            return new attcertissuer(v2form.getinstance((asn1taggedobject)obj, false));
        }
        else if (obj instanceof asn1sequence)
        {
            return new attcertissuer(generalnames.getinstance(obj));
        }

        throw new illegalargumentexception("unknown object in factory: " + obj.getclass().getname());
    }
    
    public static attcertissuer getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(obj.getobject()); // must be explicitly tagged
    }

    /**
     * don't use this one if you are trying to be rfc 3281 compliant.
     * use it for v1 attribute certificates only.
     * 
     * @param names our generalnames structure
     */
    public attcertissuer(
        generalnames  names)
    {
        obj = names;
        choiceobj = obj.toasn1primitive();
    }
    
    public attcertissuer(
        v2form  v2form)
    {
        obj = v2form;
        choiceobj = new dertaggedobject(false, 0, obj);
    }

    public asn1encodable getissuer()
    {
        return obj;
    }
    
    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  attcertissuer ::= choice {
     *       v1form   generalnames,  -- must not be used in this
     *                               -- profile
     *       v2form   [0] v2form     -- v2 only
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return choiceobj;
    }
}
