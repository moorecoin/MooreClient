package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * this class helps to support crosscerfificatepairs in a ldap directory
 * according rfc 2587
 * 
 * <pre>
 *     crosscertificatepairattribute::={
 *       with syntax   certificatepair
 *       equality matching rule certificatepairexactmatch
 *       id joint-iso-ccitt(2) ds(5) attributetype(4) crosscertificatepair(40)}
 * </pre>
 * 
 * <blockquote> the forward elements of the crosscertificatepair attribute of a
 * ca's directory entry shall be used to store all, except self-issued
 * certificates issued to this ca. optionally, the reverse elements of the
 * crosscertificatepair attribute, of a ca's directory entry may contain a
 * subset of certificates issued by this ca to other cas. when both the forward
 * and the reverse elements are present in a single attribute value, issuer name
 * in one certificate shall match the subject name in the other and vice versa,
 * and the subject public key in one certificate shall be capable of verifying
 * the digital signature on the other certificate and vice versa.
 * 
 * when a reverse element is present, the forward element value and the reverse
 * element value need not be stored in the same attribute value; in other words,
 * they can be stored in either a single attribute value or two attribute
 * values. </blockquote>
 * 
 * <pre>
 *       certificatepair ::= sequence {
 *         forward        [0]    certificate optional,
 *         reverse        [1]    certificate optional,
 *         -- at least one of the pair shall be present -- } 
 * </pre>
 */
public class certificatepair
    extends asn1object
{
    private certificate forward;

    private certificate reverse;

    public static certificatepair getinstance(object obj)
    {
        if (obj == null || obj instanceof certificatepair)
        {
            return (certificatepair)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new certificatepair((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * the sequence is of type certificatepair:
     * <p/>
     * <pre>
     *       certificatepair ::= sequence {
     *         forward        [0]    certificate optional,
     *         reverse        [1]    certificate optional,
     *         -- at least one of the pair shall be present -- }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private certificatepair(asn1sequence seq)
    {
        if (seq.size() != 1 && seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }

        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1taggedobject o = asn1taggedobject.getinstance(e.nextelement());
            if (o.gettagno() == 0)
            {
                forward = certificate.getinstance(o, true);
            }
            else if (o.gettagno() == 1)
            {
                reverse = certificate.getinstance(o, true);
            }
            else
            {
                throw new illegalargumentexception("bad tag number: "
                    + o.gettagno());
            }
        }
    }

    /**
     * constructor from a given details.
     *
     * @param forward certificates issued to this ca.
     * @param reverse certificates issued by this ca to other cas.
     */
    public certificatepair(certificate forward, certificate reverse)
    {
        this.forward = forward;
        this.reverse = reverse;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *       certificatepair ::= sequence {
     *         forward        [0]    certificate optional,
     *         reverse        [1]    certificate optional,
     *         -- at least one of the pair shall be present -- }
     * </pre>
     *
     * @return a asn1primitive
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();

        if (forward != null)
        {
            vec.add(new dertaggedobject(0, forward));
        }
        if (reverse != null)
        {
            vec.add(new dertaggedobject(1, reverse));
        }

        return new dersequence(vec);
    }

    /**
     * @return returns the forward.
     */
    public certificate getforward()
    {
        return forward;
    }

    /**
     * @return returns the reverse.
     */
    public certificate getreverse()
    {
        return reverse;
    }
}
