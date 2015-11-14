package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class certid
    extends asn1object
{
    algorithmidentifier    hashalgorithm;
    asn1octetstring        issuernamehash;
    asn1octetstring        issuerkeyhash;
    asn1integer             serialnumber;

    public certid(
        algorithmidentifier hashalgorithm,
        asn1octetstring     issuernamehash,
        asn1octetstring     issuerkeyhash,
        asn1integer         serialnumber)
    {
        this.hashalgorithm = hashalgorithm;
        this.issuernamehash = issuernamehash;
        this.issuerkeyhash = issuerkeyhash;
        this.serialnumber = serialnumber;
    }

    private certid(
        asn1sequence    seq)
    {
        hashalgorithm = algorithmidentifier.getinstance(seq.getobjectat(0));
        issuernamehash = (asn1octetstring)seq.getobjectat(1);
        issuerkeyhash = (asn1octetstring)seq.getobjectat(2);
        serialnumber = (asn1integer)seq.getobjectat(3);
    }

    public static certid getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static certid getinstance(
        object  obj)
    {
        if (obj instanceof certid)
        {
            return (certid)obj;
        }
        else if (obj != null)
        {
            return new certid(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public algorithmidentifier gethashalgorithm()
    {
        return hashalgorithm;
    }

    public asn1octetstring getissuernamehash()
    {
        return issuernamehash;
    }

    public asn1octetstring getissuerkeyhash()
    {
        return issuerkeyhash;
    }

    public asn1integer getserialnumber()
    {
        return serialnumber;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * certid          ::=     sequence {
     *     hashalgorithm       algorithmidentifier,
     *     issuernamehash      octet string, -- hash of issuer's dn
     *     issuerkeyhash       octet string, -- hash of issuers public key
     *     serialnumber        certificateserialnumber }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(hashalgorithm);
        v.add(issuernamehash);
        v.add(issuerkeyhash);
        v.add(serialnumber);

        return new dersequence(v);
    }
}
