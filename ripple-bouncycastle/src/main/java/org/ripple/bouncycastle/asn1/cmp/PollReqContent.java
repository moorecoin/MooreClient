package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class pollreqcontent
    extends asn1object
{
    private asn1sequence content;

    private pollreqcontent(asn1sequence seq)
    {
        content = seq;
    }

    public static pollreqcontent getinstance(object o)
    {
        if (o instanceof pollreqcontent)
        {
            return (pollreqcontent)o;
        }

        if (o != null)
        {
            return new pollreqcontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    /**
     * create a pollreqcontent for a single certreqid.
     *
     * @param certreqid the certificate request id.
     */
    public pollreqcontent(asn1integer certreqid)
    {
        this(new dersequence(new dersequence(certreqid)));
    }

    public asn1integer[][] getcertreqids()
    {
        asn1integer[][] result = new asn1integer[content.size()][];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = sequencetoasn1integerarray((asn1sequence)content.getobjectat(i));
        }

        return result;
    }

    private static asn1integer[] sequencetoasn1integerarray(asn1sequence seq)
    {
         asn1integer[] result = new asn1integer[seq.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = asn1integer.getinstance(seq.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * pollreqcontent ::= sequence of sequence {
     *                        certreqid              integer
     * }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
