package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * class for containing a restriction object subtrees in nameconstraints. see
 * rfc 3280.
 * 
 * <pre>
 *       
 *       generalsubtree ::= sequence 
 *       {
 *         base                    generalname,
 *         minimum         [0]     basedistance default 0,
 *         maximum         [1]     basedistance optional 
 *       }
 * </pre>
 * 
 * @see org.ripple.bouncycastle.asn1.x509.nameconstraints
 * 
 */
public class generalsubtree 
    extends asn1object
{
    private static final biginteger zero = biginteger.valueof(0);

    private generalname base;

    private asn1integer minimum;

    private asn1integer maximum;

    private generalsubtree(
        asn1sequence seq) 
    {
        base = generalname.getinstance(seq.getobjectat(0));

        switch (seq.size()) 
        {
        case 1:
            break;
        case 2:
            asn1taggedobject o = asn1taggedobject.getinstance(seq.getobjectat(1));
            switch (o.gettagno()) 
            {
            case 0:
                minimum = asn1integer.getinstance(o, false);
                break;
            case 1:
                maximum = asn1integer.getinstance(o, false);
                break;
            default:
                throw new illegalargumentexception("bad tag number: "
                        + o.gettagno());
            }
            break;
        case 3:
        {
            {
                asn1taggedobject omin = asn1taggedobject.getinstance(seq.getobjectat(1));
                if (omin.gettagno() != 0)
                {
                    throw new illegalargumentexception("bad tag number for 'minimum': " + omin.gettagno());
                }
                minimum = asn1integer.getinstance(omin, false);
            }

            {
                asn1taggedobject omax = asn1taggedobject.getinstance(seq.getobjectat(2));
                if (omax.gettagno() != 1)
                {
                    throw new illegalargumentexception("bad tag number for 'maximum': " + omax.gettagno());
                }
                maximum = asn1integer.getinstance(omax, false);
            }

            break;
        }
        default:
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }
    }

    /**
     * constructor from a given details.
     * 
     * according rfc 3280, the minimum and maximum fields are not used with any
     * name forms, thus minimum must be zero, and maximum must be absent.
     * <p>
     * if minimum is <code>null</code>, zero is assumed, if
     * maximum is <code>null</code>, maximum is absent.
     * 
     * @param base
     *            a restriction.
     * @param minimum
     *            minimum
     * 
     * @param maximum
     *            maximum
     */
    public generalsubtree(
        generalname base,
        biginteger minimum,
        biginteger maximum)
    {
        this.base = base;
        if (maximum != null)
        {
            this.maximum = new asn1integer(maximum);
        }
        if (minimum == null)
        {
            this.minimum = null;
        }
        else
        {
            this.minimum = new asn1integer(minimum);
        }
    }

    public generalsubtree(generalname base)
    {
        this(base, null, null);
    }

    public static generalsubtree getinstance(
        asn1taggedobject o,
        boolean explicit)
    {
        return new generalsubtree(asn1sequence.getinstance(o, explicit));
    }

    public static generalsubtree getinstance(
        object obj)
    {
        if (obj == null)
        {
            return null;
        }

        if (obj instanceof generalsubtree)
        {
            return (generalsubtree) obj;
        }

        return new generalsubtree(asn1sequence.getinstance(obj));
    }

    public generalname getbase()
    {
        return base;
    }

    public biginteger getminimum()
    {
        if (minimum == null)
        {
            return zero;
        }

        return minimum.getvalue();
    }

    public biginteger getmaximum()
    {
        if (maximum == null)
        {
            return null;
        }

        return maximum.getvalue();
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * 
     * returns:
     * 
     * <pre>
     *       generalsubtree ::= sequence 
     *       {
     *         base                    generalname,
     *         minimum         [0]     basedistance default 0,
     *         maximum         [1]     basedistance optional 
     *       }
     * </pre>
     * 
     * @return a asn1primitive
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(base);

        if (minimum != null && !minimum.getvalue().equals(zero))
        {
            v.add(new dertaggedobject(false, 0, minimum));
        }

        if (maximum != null)
        {
            v.add(new dertaggedobject(false, 1, maximum));
        }

        return new dersequence(v);
    }
}
