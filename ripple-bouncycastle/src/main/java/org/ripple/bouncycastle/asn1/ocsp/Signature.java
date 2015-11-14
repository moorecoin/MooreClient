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

public class signature
    extends asn1object
{
    algorithmidentifier signaturealgorithm;
    derbitstring        signature;
    asn1sequence        certs;

    public signature(
        algorithmidentifier signaturealgorithm,
        derbitstring        signature)
    {
        this.signaturealgorithm = signaturealgorithm;
        this.signature = signature;
    }

    public signature(
        algorithmidentifier signaturealgorithm,
        derbitstring        signature,
        asn1sequence        certs)
    {
        this.signaturealgorithm = signaturealgorithm;
        this.signature = signature;
        this.certs = certs;
    }

    private signature(
        asn1sequence    seq)
    {
        signaturealgorithm  = algorithmidentifier.getinstance(seq.getobjectat(0));
        signature = (derbitstring)seq.getobjectat(1);

        if (seq.size() == 3)
        {
            certs = asn1sequence.getinstance(
                                (asn1taggedobject)seq.getobjectat(2), true);
        }
    }

    public static signature getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static signature getinstance(
        object  obj)
    {
        if (obj instanceof signature)
        {
            return (signature)obj;
        }
        else if (obj != null)
        {
            return new signature(asn1sequence.getinstance(obj));
        }

        return null;
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
     * signature       ::=     sequence {
     *     signaturealgorithm      algorithmidentifier,
     *     signature               bit string,
     *     certs               [0] explicit sequence of certificate optional}
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(signaturealgorithm);
        v.add(signature);

        if (certs != null)
        {
            v.add(new dertaggedobject(true, 0, certs));
        }

        return new dersequence(v);
    }
}
