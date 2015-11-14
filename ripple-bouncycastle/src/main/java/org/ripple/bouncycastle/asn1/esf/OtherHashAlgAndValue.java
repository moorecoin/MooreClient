package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class otherhashalgandvalue
    extends asn1object
{
    private algorithmidentifier hashalgorithm;
    private asn1octetstring     hashvalue;


    public static otherhashalgandvalue getinstance(
        object obj)
    {
        if (obj instanceof otherhashalgandvalue)
        {
            return (otherhashalgandvalue) obj;
        }
        else if (obj != null)
        {
            return new otherhashalgandvalue(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private otherhashalgandvalue(
        asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        hashalgorithm = algorithmidentifier.getinstance(seq.getobjectat(0));
        hashvalue = asn1octetstring.getinstance(seq.getobjectat(1));
    }

    public otherhashalgandvalue(
        algorithmidentifier hashalgorithm,
        asn1octetstring     hashvalue)
    {
        this.hashalgorithm = hashalgorithm;
        this.hashvalue = hashvalue;
    }

    public algorithmidentifier gethashalgorithm()
    {
        return hashalgorithm;
    }

    public asn1octetstring gethashvalue()
    {
        return hashvalue;
    }

    /**
     * <pre>
     * otherhashalgandvalue ::= sequence {
     *     hashalgorithm algorithmidentifier,
     *     hashvalue otherhashvalue }
     *
     * otherhashvalue ::= octet string
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(hashalgorithm);
        v.add(hashvalue);

        return new dersequence(v);
    }
}
