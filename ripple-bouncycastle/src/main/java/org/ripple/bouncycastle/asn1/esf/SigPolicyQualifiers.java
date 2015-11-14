package org.ripple.bouncycastle.asn1.esf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class sigpolicyqualifiers
    extends asn1object
{
    asn1sequence qualifiers;

    public static sigpolicyqualifiers getinstance(
        object obj)
    {
        if (obj instanceof sigpolicyqualifiers)
        {
            return (sigpolicyqualifiers) obj;
        }
        else if (obj instanceof asn1sequence)
        {
            return new sigpolicyqualifiers(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private sigpolicyqualifiers(
        asn1sequence seq)
    {
        qualifiers = seq;
    }

    public sigpolicyqualifiers(
        sigpolicyqualifierinfo[] qualifierinfos)
    {
        asn1encodablevector v = new asn1encodablevector();
        for (int i=0; i < qualifierinfos.length; i++)
        {
            v.add(qualifierinfos[i]);
        }
        qualifiers = new dersequence(v);
    }

    /**
     * return the number of qualifier info elements present.
     *
     * @return number of elements present.
     */
    public int size()
    {
        return qualifiers.size();
    }

    /**
     * return the sigpolicyqualifierinfo at index i.
     *
     * @param i index of the info of interest
     * @return the info at index i.
     */
    public sigpolicyqualifierinfo getinfoat(
        int i)
    {
        return sigpolicyqualifierinfo.getinstance(qualifiers.getobjectat(i));
    }

    /**
     * <pre>
     * sigpolicyqualifiers ::= sequence size (1..max) of sigpolicyqualifierinfo
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return qualifiers;
    }
}
