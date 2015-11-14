package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;


public class recipientencryptedkey
    extends asn1object
{
    private keyagreerecipientidentifier identifier;
    private asn1octetstring encryptedkey;

    private recipientencryptedkey(
        asn1sequence seq)
    {
        identifier = keyagreerecipientidentifier.getinstance(seq.getobjectat(0));
        encryptedkey = (asn1octetstring)seq.getobjectat(1);
    }
    
    /**
     * return an recipientencryptedkey object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static recipientencryptedkey getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return a recipientencryptedkey object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static recipientencryptedkey getinstance(
        object obj)
    {
        if (obj == null || obj instanceof recipientencryptedkey)
        {
            return (recipientencryptedkey)obj;
        }
        
        if (obj instanceof asn1sequence)
        {
            return new recipientencryptedkey((asn1sequence)obj);
        }
        
        throw new illegalargumentexception("invalid recipientencryptedkey: " + obj.getclass().getname());
    } 

    public recipientencryptedkey(
        keyagreerecipientidentifier id,
        asn1octetstring             encryptedkey)
    {
        this.identifier = id;
        this.encryptedkey = encryptedkey;
    }

    public keyagreerecipientidentifier getidentifier()
    {
        return identifier;
    }

    public asn1octetstring getencryptedkey()
    {
        return encryptedkey;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * recipientencryptedkey ::= sequence {
     *     rid keyagreerecipientidentifier,
     *     encryptedkey encryptedkey
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(identifier);
        v.add(encryptedkey);

        return new dersequence(v);
    }
}
