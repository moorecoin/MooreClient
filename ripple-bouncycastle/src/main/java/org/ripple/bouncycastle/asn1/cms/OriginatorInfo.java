package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class originatorinfo
    extends asn1object
{
    private asn1set certs;
    private asn1set crls;
    
    public originatorinfo(
        asn1set certs,
        asn1set crls)
    {
        this.certs = certs;
        this.crls = crls;
    }
    
    private originatorinfo(
        asn1sequence seq)
    {
        switch (seq.size())
        {
        case 0:     // empty
            break;
        case 1:
            asn1taggedobject o = (asn1taggedobject)seq.getobjectat(0);
            switch (o.gettagno())
            {
            case 0 :
                certs = asn1set.getinstance(o, false);
                break;
            case 1 :
                crls = asn1set.getinstance(o, false);
                break;
            default:
                throw new illegalargumentexception("bad tag in originatorinfo: " + o.gettagno());
            }
            break;
        case 2:
            certs = asn1set.getinstance((asn1taggedobject)seq.getobjectat(0), false);
            crls  = asn1set.getinstance((asn1taggedobject)seq.getobjectat(1), false);
            break;
        default:
            throw new illegalargumentexception("originatorinfo too big");
        }
    }
    
    /**
     * return an originatorinfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static originatorinfo getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return an originatorinfo object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static originatorinfo getinstance(
        object obj)
    {
        if (obj instanceof originatorinfo)
        {
            return (originatorinfo)obj;
        }
        else if (obj != null)
        {
            return new originatorinfo(asn1sequence.getinstance(obj));
        }
        
        return null;
    }
    
    public asn1set getcertificates()
    {
        return certs;
    }

    public asn1set getcrls()
    {
        return crls;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * originatorinfo ::= sequence {
     *     certs [0] implicit certificateset optional,
     *     crls [1] implicit certificaterevocationlists optional 
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        if (certs != null)
        {
            v.add(new dertaggedobject(false, 0, certs));
        }
        
        if (crls != null)
        {
            v.add(new dertaggedobject(false, 1, crls));
        }
        
        return new dersequence(v);
    }
}
