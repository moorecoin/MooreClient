package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class kekidentifier
    extends asn1object
{
    private asn1octetstring    keyidentifier;
    private asn1generalizedtime date;
    private otherkeyattribute  other;
    
    public kekidentifier(
        byte[]              keyidentifier,
        asn1generalizedtime  date,
        otherkeyattribute   other)
    {
        this.keyidentifier = new deroctetstring(keyidentifier);
        this.date = date;
        this.other = other;
    }
    
    private kekidentifier(
        asn1sequence seq)
    {
        keyidentifier = (asn1octetstring)seq.getobjectat(0);
        
        switch (seq.size())
        {
        case 1:
            break;
        case 2:
            if (seq.getobjectat(1) instanceof asn1generalizedtime)
            {
                date = (asn1generalizedtime)seq.getobjectat(1); 
            }
            else
            {
                other = otherkeyattribute.getinstance(seq.getobjectat(1));
            }
            break;
        case 3:
            date  = (asn1generalizedtime)seq.getobjectat(1);
            other = otherkeyattribute.getinstance(seq.getobjectat(2));
            break;
        default:
                throw new illegalargumentexception("invalid kekidentifier");
        }
    }

    /**
     * return a kekidentifier object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static kekidentifier getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return a kekidentifier object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static kekidentifier getinstance(
        object obj)
    {
        if (obj == null || obj instanceof kekidentifier)
        {
            return (kekidentifier)obj;
        }
        
        if (obj instanceof asn1sequence)
        {
            return new kekidentifier((asn1sequence)obj);
        }
        
        throw new illegalargumentexception("invalid kekidentifier: " + obj.getclass().getname());
    }

    public asn1octetstring getkeyidentifier()
    {
        return keyidentifier;
    }

    public asn1generalizedtime getdate()
    {
        return date;
    }

    public otherkeyattribute getother()
    {
        return other;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * kekidentifier ::= sequence {
     *     keyidentifier octet string,
     *     date generalizedtime optional,
     *     other otherkeyattribute optional 
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(keyidentifier);
        
        if (date != null)
        {
            v.add(date);
        }

        if (other != null)
        {
            v.add(other);
        }
        
        return new dersequence(v);
    }
}
