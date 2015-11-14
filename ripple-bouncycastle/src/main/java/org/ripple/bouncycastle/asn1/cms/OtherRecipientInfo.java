package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class otherrecipientinfo
    extends asn1object
{
    private asn1objectidentifier    oritype;
    private asn1encodable           orivalue;

    public otherrecipientinfo(
        asn1objectidentifier     oritype,
        asn1encodable            orivalue)
    {
        this.oritype = oritype;
        this.orivalue = orivalue;
    }

    /**
     * @deprecated use getinstance().
     * @param seq
     */
    public otherrecipientinfo(
        asn1sequence seq)
    {
        oritype = asn1objectidentifier.getinstance(seq.getobjectat(0));
        orivalue = seq.getobjectat(1);
    }

    /**
     * return a otherrecipientinfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static otherrecipientinfo getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return a otherrecipientinfo object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static otherrecipientinfo getinstance(
        object obj)
    {
        if (obj instanceof otherrecipientinfo)
        {
            return (otherrecipientinfo)obj;
        }
        
        if (obj != null)
        {
            return new otherrecipientinfo(asn1sequence.getinstance(obj));
        }
        
        return null;
    }

    public asn1objectidentifier gettype()
    {
        return oritype;
    }

    public asn1encodable getvalue()
    {
        return orivalue;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * otherrecipientinfo ::= sequence {
     *    oritype object identifier,
     *    orivalue any defined by oritype }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(oritype);
        v.add(orivalue);

        return new dersequence(v);
    }
}
