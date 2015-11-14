package org.ripple.bouncycastle.asn1.esf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * <pre>
 * ocsplistid ::=  sequence {
 *    ocspresponses  sequence of ocspresponsesid
 * }
 * </pre>
 */
public class ocsplistid
    extends asn1object
{
    private asn1sequence ocspresponses;

    public static ocsplistid getinstance(object obj)
    {
        if (obj instanceof ocsplistid)
        {
            return (ocsplistid)obj;
        }
        else if (obj != null)
        {
            return new ocsplistid(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private ocsplistid(asn1sequence seq)
    {
        if (seq.size() != 1)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        this.ocspresponses = (asn1sequence)seq.getobjectat(0);
        enumeration e = this.ocspresponses.getobjects();
        while (e.hasmoreelements())
        {
            ocspresponsesid.getinstance(e.nextelement());
        }
    }

    public ocsplistid(ocspresponsesid[] ocspresponses)
    {
        this.ocspresponses = new dersequence(ocspresponses);
    }

    public ocspresponsesid[] getocspresponses()
    {
        ocspresponsesid[] result = new ocspresponsesid[this.ocspresponses
            .size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = ocspresponsesid.getinstance(this.ocspresponses
                .getobjectat(idx));
        }
        return result;
    }

    public asn1primitive toasn1primitive()
    {
        return new dersequence(this.ocspresponses);
    }
}
