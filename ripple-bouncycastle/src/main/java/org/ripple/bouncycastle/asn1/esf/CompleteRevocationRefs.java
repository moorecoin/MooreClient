package org.ripple.bouncycastle.asn1.esf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * <pre>
 * completerevocationrefs ::= sequence of crlocspref
 * </pre>
 */
public class completerevocationrefs
    extends asn1object
{

    private asn1sequence crlocsprefs;

    public static completerevocationrefs getinstance(object obj)
    {
        if (obj instanceof completerevocationrefs)
        {
            return (completerevocationrefs)obj;
        }
        else if (obj != null)
        {
            return new completerevocationrefs(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private completerevocationrefs(asn1sequence seq)
    {
        enumeration seqenum = seq.getobjects();
        while (seqenum.hasmoreelements())
        {
            crlocspref.getinstance(seqenum.nextelement());
        }
        this.crlocsprefs = seq;
    }

    public completerevocationrefs(crlocspref[] crlocsprefs)
    {
        this.crlocsprefs = new dersequence(crlocsprefs);
    }

    public crlocspref[] getcrlocsprefs()
    {
        crlocspref[] result = new crlocspref[this.crlocsprefs.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = crlocspref.getinstance(this.crlocsprefs
                .getobjectat(idx));
        }
        return result;
    }

    public asn1primitive toasn1primitive()
    {
        return this.crlocsprefs;
    }
}
