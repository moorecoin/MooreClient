package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class pkipublicationinfo
    extends asn1object
{
    private asn1integer action;
    private asn1sequence pubinfos;

    private pkipublicationinfo(asn1sequence seq)
    {
        action = asn1integer.getinstance(seq.getobjectat(0));
        pubinfos = asn1sequence.getinstance(seq.getobjectat(1));
    }

    public static pkipublicationinfo getinstance(object o)
    {
        if (o instanceof pkipublicationinfo)
        {
            return (pkipublicationinfo)o;
        }

        if (o != null)
        {
            return new pkipublicationinfo(asn1sequence.getinstance(o));
        }

        return null;
    }

    public asn1integer getaction()
    {
        return action;
    }

    public singlepubinfo[] getpubinfos()
    {
        if (pubinfos == null)
        {
            return null;
        }

        singlepubinfo[] results = new singlepubinfo[pubinfos.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = singlepubinfo.getinstance(pubinfos.getobjectat(i));
        }

        return results;
    }

    /**
     * <pre>
     * pkipublicationinfo ::= sequence {
     *                  action     integer {
     *                                 dontpublish (0),
     *                                 pleasepublish (1) },
     *                  pubinfos  sequence size (1..max) of singlepubinfo optional }
     * -- pubinfos must not be present if action is "dontpublish"
     * -- (if action is "pleasepublish" and pubinfos is omitted,
     * -- "dontcare" is assumed)
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(action);
        v.add(pubinfos);

        return new dersequence(v);
    }
}
