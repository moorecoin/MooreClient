package org.ripple.bouncycastle.asn1.mozilla;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;

/**
 * this is designed to parse
 * the publickeyandchallenge created by the keygen tag included by
 * mozilla based browsers.
 *  <pre>
 *  publickeyandchallenge ::= sequence {
 *    spki subjectpublickeyinfo,
 *    challenge ia5string
 *  }
 *
 *  </pre>
 */
public class publickeyandchallenge
    extends asn1object
{
    private asn1sequence         pkacseq;
    private subjectpublickeyinfo spki;
    private deria5string         challenge;

    public static publickeyandchallenge getinstance(object obj)
    {
        if (obj instanceof publickeyandchallenge)
        {
            return (publickeyandchallenge)obj;
        }
        else if (obj != null)
        {
            return new publickeyandchallenge(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private publickeyandchallenge(asn1sequence seq)
    {
        pkacseq = seq;
        spki = subjectpublickeyinfo.getinstance(seq.getobjectat(0));
        challenge = deria5string.getinstance(seq.getobjectat(1));
    }

    public asn1primitive toasn1primitive()
    {
        return pkacseq;
    }

    public subjectpublickeyinfo getsubjectpublickeyinfo()
    {
        return spki;
    }

    public deria5string getchallenge()
    {
        return challenge;
    }
}
