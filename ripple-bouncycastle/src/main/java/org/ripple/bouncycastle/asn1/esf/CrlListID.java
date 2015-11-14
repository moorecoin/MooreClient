package org.ripple.bouncycastle.asn1.esf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * <pre>
 * crllistid ::= sequence {
 *     crls sequence of crlvalidatedid }
 * </pre>
 */
public class crllistid
    extends asn1object
{

    private asn1sequence crls;

    public static crllistid getinstance(object obj)
    {
        if (obj instanceof crllistid)
        {
            return (crllistid)obj;
        }
        else if (obj != null)
        {
            return new crllistid(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private crllistid(asn1sequence seq)
    {
        this.crls = (asn1sequence)seq.getobjectat(0);
        enumeration e = this.crls.getobjects();
        while (e.hasmoreelements())
        {
            crlvalidatedid.getinstance(e.nextelement());
        }
    }

    public crllistid(crlvalidatedid[] crls)
    {
        this.crls = new dersequence(crls);
    }

    public crlvalidatedid[] getcrls()
    {
        crlvalidatedid[] result = new crlvalidatedid[this.crls.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = crlvalidatedid
                .getinstance(this.crls.getobjectat(idx));
        }
        return result;
    }

    public asn1primitive toasn1primitive()
    {
        return new dersequence(this.crls);
    }
}
