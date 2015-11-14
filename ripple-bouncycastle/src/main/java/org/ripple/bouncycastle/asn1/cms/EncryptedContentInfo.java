package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.bertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class encryptedcontentinfo
    extends asn1object
{
    private asn1objectidentifier contenttype;
    private algorithmidentifier contentencryptionalgorithm;
    private asn1octetstring     encryptedcontent;
    
    public encryptedcontentinfo(
        asn1objectidentifier contenttype, 
        algorithmidentifier contentencryptionalgorithm,
        asn1octetstring     encryptedcontent)
    {
        this.contenttype = contenttype;
        this.contentencryptionalgorithm = contentencryptionalgorithm;
        this.encryptedcontent = encryptedcontent;
    }
    
    private encryptedcontentinfo(
        asn1sequence seq)
    {
        if (seq.size() < 2)
        {
            throw new illegalargumentexception("truncated sequence found");
        }

        contenttype = (asn1objectidentifier)seq.getobjectat(0);
        contentencryptionalgorithm = algorithmidentifier.getinstance(
                                                        seq.getobjectat(1));
        if (seq.size() > 2)
        {
            encryptedcontent = asn1octetstring.getinstance(
                                (asn1taggedobject)seq.getobjectat(2), false);
        }
    }

    /**
     * return an encryptedcontentinfo object from the given object.
     *
     * @param obj the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static encryptedcontentinfo getinstance(
        object obj)
    {
        if (obj instanceof encryptedcontentinfo)
        {
            return (encryptedcontentinfo)obj;
        }
        if (obj != null)
        {
            return new encryptedcontentinfo(asn1sequence.getinstance(obj));
        }
        
        return null;
    }

    public asn1objectidentifier getcontenttype()
    {
        return contenttype;
    }

    public algorithmidentifier getcontentencryptionalgorithm()
    {
        return contentencryptionalgorithm;
    }

    public asn1octetstring getencryptedcontent()
    {
        return encryptedcontent;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * encryptedcontentinfo ::= sequence {
     *     contenttype contenttype,
     *     contentencryptionalgorithm contentencryptionalgorithmidentifier,
     *     encryptedcontent [0] implicit encryptedcontent optional 
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();
        
        v.add(contenttype);
        v.add(contentencryptionalgorithm);

        if (encryptedcontent != null)
        {
            v.add(new bertaggedobject(false, 0, encryptedcontent));
        }
        
        return new bersequence(v);
    }
}
