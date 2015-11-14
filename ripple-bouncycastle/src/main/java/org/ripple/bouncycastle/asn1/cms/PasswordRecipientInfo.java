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

public class passwordrecipientinfo
    extends asn1object
{
    private asn1integer          version;
    private algorithmidentifier keyderivationalgorithm;
    private algorithmidentifier keyencryptionalgorithm;
    private asn1octetstring     encryptedkey;

    public passwordrecipientinfo(
        algorithmidentifier     keyencryptionalgorithm,
        asn1octetstring         encryptedkey)
    {
        this.version = new asn1integer(0);
        this.keyencryptionalgorithm = keyencryptionalgorithm;
        this.encryptedkey = encryptedkey;
    }
    
    public passwordrecipientinfo(
        algorithmidentifier     keyderivationalgorithm,
        algorithmidentifier     keyencryptionalgorithm,
        asn1octetstring         encryptedkey)
    {
        this.version = new asn1integer(0);
        this.keyderivationalgorithm = keyderivationalgorithm;
        this.keyencryptionalgorithm = keyencryptionalgorithm;
        this.encryptedkey = encryptedkey;
    }
    
    public passwordrecipientinfo(
        asn1sequence seq)
    {
        version = (asn1integer)seq.getobjectat(0);
        if (seq.getobjectat(1) instanceof asn1taggedobject)
        {
            keyderivationalgorithm = algorithmidentifier.getinstance((asn1taggedobject)seq.getobjectat(1), false);
            keyencryptionalgorithm = algorithmidentifier.getinstance(seq.getobjectat(2));
            encryptedkey = (asn1octetstring)seq.getobjectat(3);
        }
        else
        {
            keyencryptionalgorithm = algorithmidentifier.getinstance(seq.getobjectat(1));
            encryptedkey = (asn1octetstring)seq.getobjectat(2);
        }
    }

    /**
     * return a passwordrecipientinfo object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static passwordrecipientinfo getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return a passwordrecipientinfo object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static passwordrecipientinfo getinstance(
        object obj)
    {
        if (obj == null || obj instanceof passwordrecipientinfo)
        {
            return (passwordrecipientinfo)obj;
        }
        
        if(obj instanceof asn1sequence)
        {
            return new passwordrecipientinfo((asn1sequence)obj);
        }
        
        throw new illegalargumentexception("invalid passwordrecipientinfo: " + obj.getclass().getname());
    }

    public asn1integer getversion()
    {
        return version;
    }

    public algorithmidentifier getkeyderivationalgorithm()
    {
        return keyderivationalgorithm;
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
     * passwordrecipientinfo ::= sequence {
     *   version cmsversion,   -- always set to 0
     *   keyderivationalgorithm [0] keyderivationalgorithmidentifier
     *                             optional,
     *  keyencryptionalgorithm keyencryptionalgorithmidentifier,
     *  encryptedkey encryptedkey }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        
        if (keyderivationalgorithm != null)
        {
            v.add(new dertaggedobject(false, 0, keyderivationalgorithm));
        }
        v.add(keyencryptionalgorithm);
        v.add(encryptedkey);

        return new dersequence(v);
    }
}
