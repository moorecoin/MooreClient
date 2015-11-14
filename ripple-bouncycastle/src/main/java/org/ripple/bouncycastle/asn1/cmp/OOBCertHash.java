package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.crmf.certid;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class oobcerthash
    extends asn1object
{
    private algorithmidentifier hashalg;
    private certid certid;
    private derbitstring  hashval;

    private oobcerthash(asn1sequence seq)
    {
        int index = seq.size() - 1;

        hashval = derbitstring.getinstance(seq.getobjectat(index--));

        for (int i = index; i >= 0; i--)
        {
            asn1taggedobject tobj = (asn1taggedobject)seq.getobjectat(i);

            if (tobj.gettagno() == 0)
            {
                hashalg = algorithmidentifier.getinstance(tobj, true);
            }
            else
            {
                certid = certid.getinstance(tobj, true);
            }
        }

    }

    public static oobcerthash getinstance(object o)
    {
        if (o instanceof oobcerthash)
        {
            return (oobcerthash)o;
        }

        if (o != null)
        {
            return new oobcerthash(asn1sequence.getinstance(o));
        }

        return null;
    }

    public oobcerthash(algorithmidentifier hashalg, certid certid, byte[] hashval)
    {
        this(hashalg, certid, new derbitstring(hashval));
    }

    public oobcerthash(algorithmidentifier hashalg, certid certid, derbitstring hashval)
    {
        this.hashalg = hashalg;
        this.certid = certid;
        this.hashval = hashval;
    }

    public algorithmidentifier gethashalg()
    {
        return hashalg;
    }

    public certid getcertid()
    {
        return certid;
    }

    public derbitstring gethashval()
    {
        return hashval;
    }

    /**
     * <pre>
     * oobcerthash ::= sequence {
     *                      hashalg     [0] algorithmidentifier     optional,
     *                      certid      [1] certid                  optional,
     *                      hashval         bit string
     *                      -- hashval is calculated over the der encoding of the
     *                      -- self-signed certificate with the identifier certid.
     *       }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        addoptional(v, 0, hashalg);
        addoptional(v, 1, certid);

        v.add(hashval);

        return new dersequence(v);
    }

    private void addoptional(asn1encodablevector v, int tagno, asn1encodable obj)
    {
        if (obj != null)
        {
            v.add(new dertaggedobject(true, tagno, obj));
        }
    }
}
