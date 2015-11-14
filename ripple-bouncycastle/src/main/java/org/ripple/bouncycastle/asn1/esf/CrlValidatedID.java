package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * <pre>
 * crlvalidatedid ::= sequence {
 *   crlhash otherhash,
 *   crlidentifier crlidentifier optional }
 * </pre>
 */
public class crlvalidatedid
    extends asn1object
{

    private otherhash crlhash;
    private crlidentifier crlidentifier;

    public static crlvalidatedid getinstance(object obj)
    {
        if (obj instanceof crlvalidatedid)
        {
            return (crlvalidatedid)obj;
        }
        else if (obj != null)
        {
            return new crlvalidatedid(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private crlvalidatedid(asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        this.crlhash = otherhash.getinstance(seq.getobjectat(0));
        if (seq.size() > 1)
        {
            this.crlidentifier = crlidentifier.getinstance(seq.getobjectat(1));
        }
    }

    public crlvalidatedid(otherhash crlhash)
    {
        this(crlhash, null);
    }

    public crlvalidatedid(otherhash crlhash, crlidentifier crlidentifier)
    {
        this.crlhash = crlhash;
        this.crlidentifier = crlidentifier;
    }

    public otherhash getcrlhash()
    {
        return this.crlhash;
    }

    public crlidentifier getcrlidentifier()
    {
        return this.crlidentifier;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(this.crlhash.toasn1primitive());
        if (null != this.crlidentifier)
        {
            v.add(this.crlidentifier.toasn1primitive());
        }
        return new dersequence(v);
    }
}
