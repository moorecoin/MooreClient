package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * pkcs10 certification request object.
 * <pre>
 * certificationrequest ::= sequence {
 *   certificationrequestinfo  certificationrequestinfo,
 *   signaturealgorithm        algorithmidentifier{{ signaturealgorithms }},
 *   signature                 bit string
 * }
 * </pre>
 */
public class certificationrequest
    extends asn1object
{
    protected certificationrequestinfo reqinfo = null;
    protected algorithmidentifier sigalgid = null;
    protected derbitstring sigbits = null;

    public static certificationrequest getinstance(object o)
    {
        if (o instanceof certificationrequest)
        {
            return (certificationrequest)o;
        }

        if (o != null)
        {
            return new certificationrequest(asn1sequence.getinstance(o));
        }

        return null;
    }

    protected certificationrequest()
    {
    }

    public certificationrequest(
        certificationrequestinfo requestinfo,
        algorithmidentifier     algorithm,
        derbitstring            signature)
    {
        this.reqinfo = requestinfo;
        this.sigalgid = algorithm;
        this.sigbits = signature;
    }

    public certificationrequest(
        asn1sequence seq)
    {
        reqinfo = certificationrequestinfo.getinstance(seq.getobjectat(0));
        sigalgid = algorithmidentifier.getinstance(seq.getobjectat(1));
        sigbits = (derbitstring)seq.getobjectat(2);
    }

    public certificationrequestinfo getcertificationrequestinfo()
    {
        return reqinfo;
    }

    public algorithmidentifier getsignaturealgorithm()
    {
        return sigalgid;
    }

    public derbitstring getsignature()
    {
        return sigbits;
    }

    public asn1primitive toasn1primitive()
    {
        // construct the certificaterequest
        asn1encodablevector  v = new asn1encodablevector();

        v.add(reqinfo);
        v.add(sigalgid);
        v.add(sigbits);

        return new dersequence(v);
    }
}
