package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class keyagreerecipientinfo
    extends asn1object
{
    private asn1integer                  version;
    private originatoridentifierorkey   originator;
    private asn1octetstring             ukm;
    private algorithmidentifier         keyencryptionalgorithm;
    private asn1sequence                recipientencryptedkeys;
    
    public keyagreerecipientinfo(
        originatoridentifierorkey   originator,
        asn1octetstring             ukm,
        algorithmidentifier         keyencryptionalgorithm,
        asn1sequence                recipientencryptedkeys)
    {
        this.version = new asn1integer(3);
        this.originator = originator;
        this.ukm = ukm;
        this.keyencryptionalgorithm = keyencryptionalgorithm;
        this.recipientencryptedkeys = recipientencryptedkeys;
    }
    
    public keyagreerecipientinfo(
        asn1sequence seq)
    {
        int index = 0;
        
        version = (asn1integer)seq.getobjectat(index++);
        originator = originatoridentifierorkey.getinstance(
                            (asn1taggedobject)seq.getobjectat(index++), true);

        if (seq.getobjectat(index) instanceof asn1taggedobject)
        {
            ukm = asn1octetstring.getinstance(
                            (asn1taggedobject)seq.getobjectat(index++), true);
        }

        keyencryptionalgorithm = algorithmidentifier.getinstance(
                                                seq.getobjectat(index++));

        recipientencryptedkeys = (asn1sequence)seq.getobjectat(index++);
    }
    
    /**
     * return a keyagreerecipientinfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static keyagreerecipientinfo getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return a keyagreerecipientinfo object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static keyagreerecipientinfo getinstance(
        object obj)
    {
        if (obj == null || obj instanceof keyagreerecipientinfo)
        {
            return (keyagreerecipientinfo)obj;
        }
        
        if (obj instanceof asn1sequence)
        {
            return new keyagreerecipientinfo((asn1sequence)obj);
        }
        
        throw new illegalargumentexception(
        "illegal object in keyagreerecipientinfo: " + obj.getclass().getname());

    } 

    public asn1integer getversion()
    {
        return version;
    }

    public originatoridentifierorkey getoriginator()
    {
        return originator;
    }

    public asn1octetstring getuserkeyingmaterial()
    {
        return ukm;
    }

    public algorithmidentifier getkeyencryptionalgorithm()
    {
        return keyencryptionalgorithm;
    }

    public asn1sequence getrecipientencryptedkeys()
    {
        return recipientencryptedkeys;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * keyagreerecipientinfo ::= sequence {
     *     version cmsversion,  -- always set to 3
     *     originator [0] explicit originatoridentifierorkey,
     *     ukm [1] explicit userkeyingmaterial optional,
     *     keyencryptionalgorithm keyencryptionalgorithmidentifier,
     *     recipientencryptedkeys recipientencryptedkeys 
     * }
     *
     * userkeyingmaterial ::= octet string
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(new dertaggedobject(true, 0, originator));
        
        if (ukm != null)
        {
            v.add(new dertaggedobject(true, 1, ukm));
        }
        
        v.add(keyencryptionalgorithm);
        v.add(recipientencryptedkeys);

        return new dersequence(v);
    }
}
