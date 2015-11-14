package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class keyagreerecipientidentifier
    extends asn1object
    implements asn1choice
{
    private issuerandserialnumber issuerserial;
    private recipientkeyidentifier rkeyid;

    /**
     * return an keyagreerecipientidentifier object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static keyagreerecipientidentifier getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return an keyagreerecipientidentifier object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static keyagreerecipientidentifier getinstance(
        object obj)
    {
        if (obj == null || obj instanceof keyagreerecipientidentifier)
        {
            return (keyagreerecipientidentifier)obj;
        }
        
        if (obj instanceof asn1sequence)
        {
            return new keyagreerecipientidentifier(issuerandserialnumber.getinstance(obj));
        }
        
        if (obj instanceof asn1taggedobject && ((asn1taggedobject)obj).gettagno() == 0)
        {
            return new keyagreerecipientidentifier(recipientkeyidentifier.getinstance(
                (asn1taggedobject)obj, false));
        }
        
        throw new illegalargumentexception("invalid keyagreerecipientidentifier: " + obj.getclass().getname());
    } 

    public keyagreerecipientidentifier(
        issuerandserialnumber issuerserial)
    {
        this.issuerserial = issuerserial;
        this.rkeyid = null;
    }

    public keyagreerecipientidentifier(
         recipientkeyidentifier rkeyid)
    {
        this.issuerserial = null;
        this.rkeyid = rkeyid;
    }

    public issuerandserialnumber getissuerandserialnumber()
    {
        return issuerserial;
    }

    public recipientkeyidentifier getrkeyid()
    {
        return rkeyid;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * keyagreerecipientidentifier ::= choice {
     *     issuerandserialnumber issuerandserialnumber,
     *     rkeyid [0] implicit recipientkeyidentifier
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        if (issuerserial != null)
        {
            return issuerserial.toasn1primitive();
        }

        return new dertaggedobject(false, 0, rkeyid);
    }
}
