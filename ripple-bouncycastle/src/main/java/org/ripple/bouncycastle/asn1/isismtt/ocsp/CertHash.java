package org.ripple.bouncycastle.asn1.isismtt.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * isis-mtt profile: the responder may include this extension in a response to
 * send the hash of the requested certificate to the responder. this hash is
 * cryptographically bound to the certificate and serves as evidence that the
 * certificate is known to the responder (i.e. it has been issued and is present
 * in the directory). hence, this extension is a means to provide a positive
 * statement of availability as described in t8.[8]. as explained in t13.[1],
 * clients may rely on this information to be able to validate signatures after
 * the expiry of the corresponding certificate. hence, clients must support this
 * extension. if a positive statement of availability is to be delivered, this
 * extension syntax and oid must be used.
 * <p/>
 * <p/>
 * <pre>
 *     certhash ::= sequence {
 *       hashalgorithm algorithmidentifier,
 *       certificatehash octet string
 *     }
 * </pre>
 */
public class certhash
    extends asn1object
{

    private algorithmidentifier hashalgorithm;
    private byte[] certificatehash;

    public static certhash getinstance(object obj)
    {
        if (obj == null || obj instanceof certhash)
        {
            return (certhash)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new certhash((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * the sequence is of type certhash:
     * <p/>
     * <pre>
     *     certhash ::= sequence {
     *       hashalgorithm algorithmidentifier,
     *       certificatehash octet string
     *     }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private certhash(asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        hashalgorithm = algorithmidentifier.getinstance(seq.getobjectat(0));
        certificatehash = deroctetstring.getinstance(seq.getobjectat(1)).getoctets();
    }

    /**
     * constructor from a given details.
     *
     * @param hashalgorithm   the hash algorithm identifier.
     * @param certificatehash the hash of the whole der encoding of the certificate.
     */
    public certhash(algorithmidentifier hashalgorithm, byte[] certificatehash)
    {
        this.hashalgorithm = hashalgorithm;
        this.certificatehash = new byte[certificatehash.length];
        system.arraycopy(certificatehash, 0, this.certificatehash, 0,
            certificatehash.length);
    }

    public algorithmidentifier gethashalgorithm()
    {
        return hashalgorithm;
    }

    public byte[] getcertificatehash()
    {
        return certificatehash;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *     certhash ::= sequence {
     *       hashalgorithm algorithmidentifier,
     *       certificatehash octet string
     *     }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        vec.add(hashalgorithm);
        vec.add(new deroctetstring(certificatehash));
        return new dersequence(vec);
    }
}
