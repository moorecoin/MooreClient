package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class keytransrecipientinfo
    extends asn1object
{
    private asn1integer          version;
    private recipientidentifier rid;
    private algorithmidentifier keyencryptionalgorithm;
    private asn1octetstring     encryptedkey;

    public keytransrecipientinfo(
        recipientidentifier rid,
        algorithmidentifier keyencryptionalgorithm,
        asn1octetstring     encryptedkey)
    {
        if (rid.toasn1primitive() instanceof asn1taggedobject)
        {
            this.version = new asn1integer(2);
        }
        else
        {
            this.version = new asn1integer(0);
        }

        this.rid = rid;
        this.keyencryptionalgorithm = keyencryptionalgorithm;
        this.encryptedkey = encryptedkey;
    }
    
    public keytransrecipientinfo(
        asn1sequence seq)
    {
        this.version = (asn1integer)seq.getobjectat(0);
        this.rid = recipientidentifier.getinstance(seq.getobjectat(1));
        this.keyencryptionalgorithm = algorithmidentifier.getinstance(seq.getobjectat(2));
        this.encryptedkey = (asn1octetstring)seq.getobjectat(3);
    }

    /**
     * return a keytransrecipientinfo object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static keytransrecipientinfo getinstance(
        object obj)
    {
        if (obj == null || obj instanceof keytransrecipientinfo)
        {
            return (keytransrecipientinfo)obj;
        }
        
        if(obj instanceof asn1sequence)
        {
            return new keytransrecipientinfo((asn1sequence)obj);
        }
        
        throw new illegalargumentexception(
        "illegal object in keytransrecipientinfo: " + obj.getclass().getname());
    } 

    public asn1integer getversion()
    {
        return version;
    }

    public recipientidentifier getrecipientidentifier()
    {
        return rid;
    }

    public algorithmidentifier getkeyencryptionalgorithm()
    {
        return keyencryptionalgorithm;
    }

    public asn1octetstring getencryptedkey()
    {
        return encryptedkey;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * keytransrecipientinfo ::= sequence {
     *     version cmsversion,  -- always set to 0 or 2
     *     rid recipientidentifier,
     *     keyencryptionalgorithm keyencryptionalgorithmidentifier,
     *     encryptedkey encryptedkey 
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(rid);
        v.add(keyencryptionalgorithm);
        v.add(encryptedkey);

        return new dersequence(v);
    }
}
