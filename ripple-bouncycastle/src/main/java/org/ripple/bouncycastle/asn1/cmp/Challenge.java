package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class challenge
    extends asn1object
{
    private algorithmidentifier owf;
    private asn1octetstring witness;
    private asn1octetstring challenge;

    private challenge(asn1sequence seq)
    {
        int index = 0;

        if (seq.size() == 3)
        {
            owf = algorithmidentifier.getinstance(seq.getobjectat(index++));
        }

        witness = asn1octetstring.getinstance(seq.getobjectat(index++));
        challenge = asn1octetstring.getinstance(seq.getobjectat(index));
    }

    public static challenge getinstance(object o)
    {
        if (o instanceof challenge)
        {
            return (challenge)o;
        }

        if (o != null)
        {
            return new challenge(asn1sequence.getinstance(o));
        }

        return null;
    }

    public challenge(byte[] witness, byte[] challenge)
    {
        this(null, witness, challenge);
    }

    public challenge(algorithmidentifier owf, byte[] witness, byte[] challenge)
    {
        this.owf = owf;
        this.witness = new deroctetstring(witness);
        this.challenge = new deroctetstring(challenge);
    }

    public algorithmidentifier getowf()
    {
        return owf;
    }

    public byte[] getwitness()
    {
        return witness.getoctets();
    }

    public byte[] getchallenge()
    {
        return challenge.getoctets();
    }

    /**
     * <pre>
     * challenge ::= sequence {
     *                 owf                 algorithmidentifier  optional,
     *
     *                 -- must be present in the first challenge; may be omitted in
     *                 -- any subsequent challenge in popodeckeychallcontent (if
     *                 -- omitted, then the owf used in the immediately preceding
     *                 -- challenge is to be used).
     *
     *                 witness             octet string,
     *                 -- the result of applying the one-way function (owf) to a
     *                 -- randomly-generated integer, a.  [note that a different
     *                 -- integer must be used for each challenge.]
     *                 challenge           octet string
     *                 -- the encryption (under the public key for which the cert.
     *                 -- request is being made) of rand, where rand is specified as
     *                 --   rand ::= sequence {
     *                 --      int      integer,
     *                 --       - the randomly-generated integer a (above)
     *                 --      sender   generalname
     *                 --       - the sender's name (as included in pkiheader)
     *                 --   }
     *      }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        addoptional(v, owf);
        v.add(witness);
        v.add(challenge);

        return new dersequence(v);
    }

    private void addoptional(asn1encodablevector v, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(obj);
        }
    }
}
