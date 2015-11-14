package org.ripple.bouncycastle.asn1.ess;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.digestinfo;
import org.ripple.bouncycastle.asn1.x509.issuerserial;

public class othercertid
    extends asn1object
{
    private asn1encodable othercerthash;
    private issuerserial issuerserial;

    public static othercertid getinstance(object o)
    {
        if (o instanceof othercertid)
        {
            return (othercertid) o;
        }
        else if (o != null)
        {
            return new othercertid(asn1sequence.getinstance(o));
        }

        return null;
    }

    /**
     * constructor
     */
    private othercertid(asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }

        if (seq.getobjectat(0).toasn1primitive() instanceof asn1octetstring)
        {
            othercerthash = asn1octetstring.getinstance(seq.getobjectat(0));
        }
        else
        {
            othercerthash = digestinfo.getinstance(seq.getobjectat(0));

        }

        if (seq.size() > 1)
        {
            issuerserial = issuerserial.getinstance(seq.getobjectat(1));
        }
    }

    public othercertid(
        algorithmidentifier  algid,
        byte[]               digest)
    {
        this.othercerthash = new digestinfo(algid, digest);
    }

    public othercertid(
        algorithmidentifier  algid,
        byte[]               digest,
        issuerserial    issuerserial)
    {
        this.othercerthash = new digestinfo(algid, digest);
        this.issuerserial = issuerserial;
    }

    public algorithmidentifier getalgorithmhash()
    {
        if (othercerthash.toasn1primitive() instanceof asn1octetstring)
        {
            // sha-1
            return new algorithmidentifier("1.3.14.3.2.26");
        }
        else
        {
            return digestinfo.getinstance(othercerthash).getalgorithmid();
        }
    }

    public byte[] getcerthash()
    {
        if (othercerthash.toasn1primitive() instanceof asn1octetstring)
        {
            // sha-1
            return ((asn1octetstring)othercerthash.toasn1primitive()).getoctets();
        }
        else
        {
            return digestinfo.getinstance(othercerthash).getdigest();
        }
    }

    public issuerserial getissuerserial()
    {
        return issuerserial;
    }

    /**
     * <pre>
     * othercertid ::= sequence {
     *     othercerthash    otherhash,
     *     issuerserial     issuerserial optional }
     *
     * otherhash ::= choice {
     *     sha1hash     octet string,
     *     otherhash    otherhashalgandvalue }
     *
     * otherhashalgandvalue ::= sequence {
     *     hashalgorithm    algorithmidentifier,
     *     hashvalue        octet string }
     *
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(othercerthash);

        if (issuerserial != null)
        {
            v.add(issuerserial);
        }

        return new dersequence(v);
    }
}
