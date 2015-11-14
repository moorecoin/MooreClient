package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.derutf8string;

/**
 * implementation of <code>ietfattrsyntax</code> as specified by rfc3281.
 */
public class ietfattrsyntax
    extends asn1object
{
    public static final int value_octets    = 1;
    public static final int value_oid       = 2;
    public static final int value_utf8      = 3;
    generalnames            policyauthority = null;
    vector                  values          = new vector();
    int                     valuechoice     = -1;

    public static ietfattrsyntax getinstance(object obj)
    {
        if (obj instanceof ietfattrsyntax)
        {
            return (ietfattrsyntax)obj;
        }
        if (obj != null)
        {
            return new ietfattrsyntax(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     *  
     */
    private ietfattrsyntax(asn1sequence seq)
    {
        int i = 0;

        if (seq.getobjectat(0) instanceof asn1taggedobject)
        {
            policyauthority = generalnames.getinstance(((asn1taggedobject)seq.getobjectat(0)), false);
            i++;
        }
        else if (seq.size() == 2)
        { // voms fix
            policyauthority = generalnames.getinstance(seq.getobjectat(0));
            i++;
        }

        if (!(seq.getobjectat(i) instanceof asn1sequence))
        {
            throw new illegalargumentexception("non-ietfattrsyntax encoding");
        }

        seq = (asn1sequence)seq.getobjectat(i);

        for (enumeration e = seq.getobjects(); e.hasmoreelements();)
        {
            asn1primitive obj = (asn1primitive)e.nextelement();
            int type;

            if (obj instanceof asn1objectidentifier)
            {
                type = value_oid;
            }
            else if (obj instanceof derutf8string)
            {
                type = value_utf8;
            }
            else if (obj instanceof deroctetstring)
            {
                type = value_octets;
            }
            else
            {
                throw new illegalargumentexception("bad value type encoding ietfattrsyntax");
            }

            if (valuechoice < 0)
            {
                valuechoice = type;
            }

            if (type != valuechoice)
            {
                throw new illegalargumentexception("mix of value types in ietfattrsyntax");
            }

            values.addelement(obj);
        }
    }

    public generalnames getpolicyauthority()
    {
        return policyauthority;
    }

    public int getvaluetype()
    {
        return valuechoice;
    }

    public object[] getvalues()
    {
        if (this.getvaluetype() == value_octets)
        {
            asn1octetstring[] tmp = new asn1octetstring[values.size()];
            
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = (asn1octetstring)values.elementat(i);
            }
            
            return tmp;
        }
        else if (this.getvaluetype() == value_oid)
        {
            asn1objectidentifier[] tmp = new asn1objectidentifier[values.size()];
            
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = (asn1objectidentifier)values.elementat(i);
            }
            
            return tmp;
        }
        else
        {
            derutf8string[] tmp = new derutf8string[values.size()];
            
            for (int i = 0; i != tmp.length; i++)
            {
                tmp[i] = (derutf8string)values.elementat(i);
            }
            
            return tmp;
        }
    }

    /**
     * 
     * <pre>
     * 
     *  ietfattrsyntax ::= sequence {
     *    policyauthority [0] generalnames optional,
     *    values sequence of choice {
     *      octets octet string,
     *      oid object identifier,
     *      string utf8string
     *    }
     *  }
     *  
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (policyauthority != null)
        {
            v.add(new dertaggedobject(0, policyauthority));
        }

        asn1encodablevector v2 = new asn1encodablevector();

        for (enumeration i = values.elements(); i.hasmoreelements();)
        {
            v2.add((asn1encodable)i.nextelement());
        }

        v.add(new dersequence(v2));

        return new dersequence(v);
    }
}
