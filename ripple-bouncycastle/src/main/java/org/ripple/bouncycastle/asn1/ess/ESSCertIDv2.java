package org.ripple.bouncycastle.asn1.ess;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.issuerserial;

public class esscertidv2
    extends asn1object
{
    private algorithmidentifier hashalgorithm;
    private byte[]              certhash;
    private issuerserial        issuerserial;
    private static final algorithmidentifier default_alg_id = new algorithmidentifier(nistobjectidentifiers.id_sha256);

    public static esscertidv2 getinstance(
        object o)
    {
        if (o instanceof esscertidv2)
        {
            return (esscertidv2) o;
        }
        else if (o != null)
        {
            return new esscertidv2(asn1sequence.getinstance(o));
        }

        return null;
    }

    private esscertidv2(
        asn1sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        int count = 0;

        if (seq.getobjectat(0) instanceof asn1octetstring)
        {
            // default value
            this.hashalgorithm = default_alg_id;
        }
        else
        {
            this.hashalgorithm = algorithmidentifier.getinstance(seq.getobjectat(count++).toasn1primitive());
        }

        this.certhash = asn1octetstring.getinstance(seq.getobjectat(count++).toasn1primitive()).getoctets();

        if (seq.size() > count)
        {
            this.issuerserial = issuerserial.getinstance(seq.getobjectat(count));
        }
    }

    public esscertidv2(
        byte[]              certhash)
    {
        this(null, certhash, null);
    }

    public esscertidv2(
        algorithmidentifier algid,
        byte[]              certhash)
    {
        this(algid, certhash, null);
    }

    public esscertidv2(
        byte[]              certhash,
        issuerserial        issuerserial)
    {
        this(null, certhash, issuerserial);
    }

    public esscertidv2(
        algorithmidentifier algid,
        byte[]              certhash,
        issuerserial        issuerserial)
    {
        if (algid == null)
        {
            // default value
            this.hashalgorithm = default_alg_id;
        }
        else
        {
            this.hashalgorithm = algid;
        }

        this.certhash = certhash;
        this.issuerserial = issuerserial;
    }

    public algorithmidentifier gethashalgorithm()
    {
        return this.hashalgorithm;
    }

    public byte[] getcerthash()
    {
        return certhash;
    }

    public issuerserial getissuerserial()
    {
        return issuerserial;
    }

    /**
     * <pre>
     * esscertidv2 ::=  sequence {
     *     hashalgorithm     algorithmidentifier
     *              default {algorithm id-sha256},
     *     certhash          hash,
     *     issuerserial      issuerserial optional
     * }
     *
     * hash ::= octet string
     *
     * issuerserial ::= sequence {
     *     issuer         generalnames,
     *     serialnumber   certificateserialnumber
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (!hashalgorithm.equals(default_alg_id))
        {
            v.add(hashalgorithm);
        }

        v.add(new deroctetstring(certhash).toasn1primitive());

        if (issuerserial != null)
        {
            v.add(issuerserial);
        }

        return new dersequence(v);
    }

}
