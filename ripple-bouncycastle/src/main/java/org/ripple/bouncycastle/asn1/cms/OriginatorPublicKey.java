package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;


public class originatorpublickey
    extends asn1object
{
    private algorithmidentifier algorithm;
    private derbitstring        publickey;
    
    public originatorpublickey(
        algorithmidentifier algorithm,
        byte[]              publickey)
    {
        this.algorithm = algorithm;
        this.publickey = new derbitstring(publickey);
    }
    
    public originatorpublickey(
        asn1sequence seq)
    {
        algorithm = algorithmidentifier.getinstance(seq.getobjectat(0));
        publickey = (derbitstring)seq.getobjectat(1);
    }
    
    /**
     * return an originatorpublickey object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static originatorpublickey getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    /**
     * return an originatorpublickey object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static originatorpublickey getinstance(
        object obj)
    {
        if (obj == null || obj instanceof originatorpublickey)
        {
            return (originatorpublickey)obj;
        }
        
        if (obj instanceof asn1sequence)
        {
            return new originatorpublickey((asn1sequence)obj);
        }
        
        throw new illegalargumentexception("invalid originatorpublickey: " + obj.getclass().getname());
    } 

    public algorithmidentifier getalgorithm()
    {
        return algorithm;
    }

    public derbitstring getpublickey()
    {
        return publickey;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * originatorpublickey ::= sequence {
     *     algorithm algorithmidentifier,
     *     publickey bit string 
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(algorithm);
        v.add(publickey);

        return new dersequence(v);
    }
}
