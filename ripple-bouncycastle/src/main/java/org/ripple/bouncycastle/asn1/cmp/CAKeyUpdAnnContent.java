package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class cakeyupdanncontent
    extends asn1object
{
    private cmpcertificate oldwithnew;
    private cmpcertificate newwithold;
    private cmpcertificate newwithnew;

    private cakeyupdanncontent(asn1sequence seq)
    {
        oldwithnew = cmpcertificate.getinstance(seq.getobjectat(0));
        newwithold = cmpcertificate.getinstance(seq.getobjectat(1));
        newwithnew = cmpcertificate.getinstance(seq.getobjectat(2));
    }

    public static cakeyupdanncontent getinstance(object o)
    {
        if (o instanceof cakeyupdanncontent)
        {
            return (cakeyupdanncontent)o;
        }

        if (o != null)
        {
            return new cakeyupdanncontent(asn1sequence.getinstance(o));
        }

        return null;
    }

    public cakeyupdanncontent(cmpcertificate oldwithnew, cmpcertificate newwithold, cmpcertificate newwithnew)
    {
        this.oldwithnew = oldwithnew;
        this.newwithold = newwithold;
        this.newwithnew = newwithnew;
    }

    public cmpcertificate getoldwithnew()
    {
        return oldwithnew;
    }

    public cmpcertificate getnewwithold()
    {
        return newwithold;
    }

    public cmpcertificate getnewwithnew()
    {
        return newwithnew;
    }

    /**
     * <pre>
     * cakeyupdanncontent ::= sequence {
     *                             oldwithnew   cmpcertificate, -- old pub signed with new priv
     *                             newwithold   cmpcertificate, -- new pub signed with old priv
     *                             newwithnew   cmpcertificate  -- new pub signed with new priv
     *  }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(oldwithnew);
        v.add(newwithold);
        v.add(newwithnew);

        return new dersequence(v);
    }
}
