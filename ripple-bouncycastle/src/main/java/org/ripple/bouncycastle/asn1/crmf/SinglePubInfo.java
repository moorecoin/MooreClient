package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.generalname;

public class singlepubinfo
    extends asn1object
{
    private asn1integer pubmethod;
    private generalname publocation;

    private singlepubinfo(asn1sequence seq)
    {
        pubmethod = asn1integer.getinstance(seq.getobjectat(0));

        if (seq.size() == 2)
        {
            publocation = generalname.getinstance(seq.getobjectat(1));
        }
    }

    public static singlepubinfo getinstance(object o)
    {
        if (o instanceof singlepubinfo)
        {
            return (singlepubinfo)o;
        }

        if (o != null)
        {
            return new singlepubinfo(asn1sequence.getinstance(o));
        }

        return null;
    }

    public generalname getpublocation()
    {
        return publocation;
    }

    /**
     * <pre>
     * singlepubinfo ::= sequence {
     *        pubmethod    integer {
     *           dontcare    (0),
     *           x500        (1),
     *           web         (2),
     *           ldap        (3) },
     *       publocation  generalname optional }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(pubmethod);

        if (publocation != null)
        {
            v.add(publocation);
        }

        return new dersequence(v);
    }
}
