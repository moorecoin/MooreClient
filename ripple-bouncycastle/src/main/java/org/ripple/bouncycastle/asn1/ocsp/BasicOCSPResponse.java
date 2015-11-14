package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class basicocspresponse
    extends asn1object
{
    private responsedata        tbsresponsedata;
    private algorithmidentifier signaturealgorithm;
    private derbitstring        signature;
    private asn1sequence        certs;

    public basicocspresponse(
        responsedata        tbsresponsedata,
        algorithmidentifier signaturealgorithm,
        derbitstring        signature,
        asn1sequence        certs)
    {
        this.tbsresponsedata = tbsresponsedata;
        this.signaturealgorithm = signaturealgorithm;
        this.signature = signature;
        this.certs = certs;
    }

    private basicocspresponse(
        asn1sequence    seq)
    {
        this.tbsresponsedata = responsedata.getinstance(seq.getobjectat(0));
        this.signaturealgorithm = algorithmidentifier.getinstance(seq.getobjectat(1));
        this.signature = (derbitstring)seq.getobjectat(2);

        if (seq.size() > 3)
        {
            this.certs = asn1sequence.getinstance((asn1taggedobject)seq.getobjectat(3), true);
        }
    }

    public static basicocspresponse getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static basicocspresponse getinstance(
        object  obj)
    {
        if (obj instanceof basicocspresponse)
        {
            return (basicocspresponse)obj;
        }
        else if (obj != null)
        {
            return new basicocspresponse(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public responsedata gettbsresponsedata()
    {
        return tbsresponsedata;
    }

    public algorithmidentifier getsignaturealgorithm()
    {
        return signaturealgorithm;
    }

    public derbitstring getsignature()
    {
        return signature;
    }

    public asn1sequence getcerts()
    {
        return certs;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * basicocspresponse       ::= sequence {
     *      tbsresponsedata      responsedata,
     *      signaturealgorithm   algorithmidentifier,
     *      signature            bit string,
     *      certs                [0] explicit sequence of certificate optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(tbsresponsedata);
        v.add(signaturealgorithm);
        v.add(signature);
        if (certs != null)
        {
            v.add(new dertaggedobject(true, 0, certs));
        }

        return new dersequence(v);
    }
}
