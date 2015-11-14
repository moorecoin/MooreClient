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

public class kekrecipientinfo
    extends asn1object
{
    private asn1integer          version;
    private kekidentifier       kekid;
    private algorithmidentifier keyencryptionalgorithm;
    private asn1octetstring     encryptedkey;

    public kekrecipientinfo(
        kekidentifier       kekid,
        algorithmidentifier keyencryptionalgorithm,
        asn1octetstring     encryptedkey)
    {
        this.version = new asn1integer(4);
        this.kekid = kekid;
        this.keyencryptionalgorithm = keyencryptionalgorithm;
        this.encryptedkey = encryptedkey;
    }
    
    public kekrecipientinfo(
        asn1sequence seq)
    {
        version = (asn1integer)seq.getobjectat(0);
        kekid = kekidentifier.getinstance(seq.getobjectat(1));
        keyencryptionalgorithm = algorithmidentifier.getinstance(seq.getobjectat(2));
        encryptedkey = (asn1octetstring)seq.getobjectat(3);
    }

    /**
     * return a kekrecipientinfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static kekrecipientinfo getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return a kekrecipientinfo object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static kekrecipientinfo getinstance(
        object obj)
    {
        if (obj == null || obj instanceof kekrecipientinfo)
        {
            return (kekrecipientinfo)obj;
        }
        
        if(obj instanceof asn1sequence)
        {
            return new kekrecipientinfo((asn1sequence)obj);
        }
        
        throw new illegalargumentexception("invalid kekrecipientinfo: " + obj.getclass().getname());
    }

    public asn1integer getversion()
    {
        return version;
    }
    
    public kekidentifier getkekid()
    {
        return kekid;
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
     * kekrecipientinfo ::= sequence {
     *     version cmsversion,  -- always set to 4
     *     kekid kekidentifier,
     *     keyencryptionalgorithm keyencryptionalgorithmidentifier,
     *     encryptedkey encryptedkey 
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(kekid);
        v.add(keyencryptionalgorithm);
        v.add(encryptedkey);

        return new dersequence(v);
    }
}
