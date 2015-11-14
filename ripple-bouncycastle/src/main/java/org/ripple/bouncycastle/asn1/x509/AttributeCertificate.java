package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class attributecertificate
    extends asn1object
{
    attributecertificateinfo    acinfo;
    algorithmidentifier         signaturealgorithm;
    derbitstring                signaturevalue;

    /**
     * @param obj
     * @return an attributecertificate object
     */
    public static attributecertificate getinstance(object obj)
    {
        if (obj instanceof attributecertificate)
        {
            return (attributecertificate)obj;
        }
        else if (obj != null)
        {
            return new attributecertificate(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    public attributecertificate(
        attributecertificateinfo    acinfo,
        algorithmidentifier         signaturealgorithm,
        derbitstring                signaturevalue)
    {
        this.acinfo = acinfo;
        this.signaturealgorithm = signaturealgorithm;
        this.signaturevalue = signaturevalue;
    }
    
    public attributecertificate(
        asn1sequence    seq)
    {
        if (seq.size() != 3)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }

        this.acinfo = attributecertificateinfo.getinstance(seq.getobjectat(0));
        this.signaturealgorithm = algorithmidentifier.getinstance(seq.getobjectat(1));
        this.signaturevalue = derbitstring.getinstance(seq.getobjectat(2));
    }
    
    public attributecertificateinfo getacinfo()
    {
        return acinfo;
    }

    public algorithmidentifier getsignaturealgorithm()
    {
        return signaturealgorithm;
    }

    public derbitstring getsignaturevalue()
    {
        return signaturevalue;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  attributecertificate ::= sequence {
     *       acinfo               attributecertificateinfo,
     *       signaturealgorithm   algorithmidentifier,
     *       signaturevalue       bit string
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(acinfo);
        v.add(signaturealgorithm);
        v.add(signaturevalue);

        return new dersequence(v);
    }
}
