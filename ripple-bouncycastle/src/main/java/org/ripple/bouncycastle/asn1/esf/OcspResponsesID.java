package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * <pre>
 * ocspresponsesid ::= sequence {
 *    ocspidentifier ocspidentifier,
 *    ocsprephash otherhash optional
 * }
 * </pre>
 */
public class ocspresponsesid
    extends asn1object
{

    private ocspidentifier ocspidentifier;
    private otherhash ocsprephash;

    public static ocspresponsesid getinstance(object obj)
    {
        if (obj instanceof ocspresponsesid)
        {
            return (ocspresponsesid)obj;
        }
        else if (obj != null)
        {
            return new ocspresponsesid(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private ocspresponsesid(asn1sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        this.ocspidentifier = ocspidentifier.getinstance(seq.getobjectat(0));
        if (seq.size() > 1)
        {
            this.ocsprephash = otherhash.getinstance(seq.getobjectat(1));
        }
    }

    public ocspresponsesid(ocspidentifier ocspidentifier)
    {
        this(ocspidentifier, null);
    }

    public ocspresponsesid(ocspidentifier ocspidentifier, otherhash ocsprephash)
    {
        this.ocspidentifier = ocspidentifier;
        this.ocsprephash = ocsprephash;
    }

    public ocspidentifier getocspidentifier()
    {
        return this.ocspidentifier;
    }

    public otherhash getocsprephash()
    {
        return this.ocsprephash;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(this.ocspidentifier);
        if (null != this.ocsprephash)
        {
            v.add(this.ocsprephash);
        }
        return new dersequence(v);
    }
}
