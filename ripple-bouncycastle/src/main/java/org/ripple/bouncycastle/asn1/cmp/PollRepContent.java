package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class pollrepcontent
    extends asn1object
{
    private asn1integer[] certreqid;
    private asn1integer[] checkafter;
    private pkifreetext[] reason;

    private pollrepcontent(asn1sequence seq)
    {
        certreqid = new asn1integer[seq.size()];
        checkafter = new asn1integer[seq.size()];
        reason = new pkifreetext[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            asn1sequence s = asn1sequence.getinstance(seq.getobjectat(i));

            certreqid[i] = asn1integer.getinstance(s.getobjectat(0));
            checkafter[i] = asn1integer.getinstance(s.getobjectat(1));

            if (s.size() > 2)
            {
                reason[i] = pkifreetext.getinstance(s.getobjectat(2));
            }
        }
    }

    public static pollrepcontent getinstance(object o)
    {
        if (o instanceof pollrepcontent)
        {
            return (pollrepcontent)o;
        }

        if (o != null)
        {
            return new pollrepcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public pollrepcontent(asn1integer certreqid, asn1integer checkafter)
    {
        this(certreqid, checkafter, null);
    }

    public pollrepcontent(asn1integer certreqid, asn1integer checkafter, pkifreetext reason)
    {
        this.certreqid = new asn1integer[1];
        this.checkafter = new asn1integer[1];
        this.reason = new pkifreetext[1];

        this.certreqid[0] = certreqid;
        this.checkafter[0] = checkafter;
        this.reason[0] = reason;
    }

    public int size()
    {
        return certreqid.length;
    }

    public asn1integer getcertreqid(int index)
    {
        return certreqid[index];
    }

    public asn1integer getcheckafter(int index)
    {
        return checkafter[index];
    }

    public pkifreetext getreason(int index)
    {
        return reason[index];
    }

    /**
     * <pre>
     * pollrepcontent ::= sequence of sequence {
     *         certreqid              integer,
     *         checkafter             integer,  -- time in seconds
     *         reason                 pkifreetext optional
     *     }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector outer = new asn1encodablevector();

        for (int i = 0; i != certreqid.length; i++)
        {
            asn1encodablevector v = new asn1encodablevector();

            v.add(certreqid[i]);
            v.add(checkafter[i]);

            if (reason[i] != null)
            {
                v.add(reason[i]);
            }

            outer.add(new dersequence(v));
        }
        
        return new dersequence(outer);
    }
}
