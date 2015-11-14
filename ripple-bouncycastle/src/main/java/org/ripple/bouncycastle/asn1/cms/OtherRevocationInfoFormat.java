package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class otherrevocationinfoformat
    extends asn1object
{
    private asn1objectidentifier otherrevinfoformat;
    private asn1encodable otherrevinfo;

    public otherrevocationinfoformat(
        asn1objectidentifier otherrevinfoformat,
        asn1encodable otherrevinfo)
    {
        this.otherrevinfoformat = otherrevinfoformat;
        this.otherrevinfo = otherrevinfo;
    }

    private otherrevocationinfoformat(
        asn1sequence seq)
    {
        otherrevinfoformat = asn1objectidentifier.getinstance(seq.getobjectat(0));
        otherrevinfo = seq.getobjectat(1);
    }

    /**
     * return a otherrevocationinfoformat object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static otherrevocationinfoformat getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return a otherrevocationinfoformat object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static otherrevocationinfoformat getinstance(
        object obj)
    {
        if (obj instanceof otherrevocationinfoformat)
        {
            return (otherrevocationinfoformat)obj;
        }
        
        if (obj != null)
        {
            return new otherrevocationinfoformat(asn1sequence.getinstance(obj));
        }
        
        return null;
    }

    public asn1objectidentifier getinfoformat()
    {
        return otherrevinfoformat;
    }

    public asn1encodable getinfo()
    {
        return otherrevinfo;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * otherrevocationinfoformat ::= sequence {
     *      otherrevinfoformat object identifier,
     *      otherrevinfo any defined by otherrevinfoformat }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(otherrevinfoformat);
        v.add(otherrevinfo);

        return new dersequence(v);
    }
}
