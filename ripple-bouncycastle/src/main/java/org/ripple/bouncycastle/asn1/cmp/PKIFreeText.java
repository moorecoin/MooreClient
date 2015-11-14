package org.ripple.bouncycastle.asn1.cmp;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derutf8string;

public class pkifreetext
    extends asn1object
{
    asn1sequence strings;

    public static pkifreetext getinstance(
        asn1taggedobject    obj,
        boolean             explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static pkifreetext getinstance(
        object obj)
    {
        if (obj instanceof pkifreetext)
        {
            return (pkifreetext)obj;
        }
        else if (obj != null)
        {
            return new pkifreetext(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private pkifreetext(
        asn1sequence seq)
    {
        enumeration e = seq.getobjects();
        while (e.hasmoreelements())
        {
            if (!(e.nextelement() instanceof derutf8string))
            {
                throw new illegalargumentexception("attempt to insert non utf8 string into pkifreetext");
            }
        }
        
        strings = seq;
    }

    public pkifreetext(
        derutf8string p)
    {
        strings = new dersequence(p);
    }

    public pkifreetext(
        string p)
    {
        this(new derutf8string(p));
    }

    public pkifreetext(
        derutf8string[] strs)
    {
        strings = new dersequence(strs);
    }

    public pkifreetext(
        string[] strs)
    {
        asn1encodablevector v = new asn1encodablevector();
        for (int i = 0; i < strs.length; i++)
        {
            v.add(new derutf8string(strs[i]));
        }
        strings = new dersequence(v);
    }

    /**
     * return the number of string elements present.
     * 
     * @return number of elements present.
     */
    public int size()
    {
        return strings.size();
    }
    
    /**
     * return the utf8string at index i.
     * 
     * @param i index of the string of interest
     * @return the string at index i.
     */
    public derutf8string getstringat(
        int i)
    {
        return (derutf8string)strings.getobjectat(i);
    }
    
    /**
     * <pre>
     * pkifreetext ::= sequence size (1..max) of utf8string
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return strings;
    }
}
