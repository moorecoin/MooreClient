package org.ripple.bouncycastle.asn1.pkcs;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class dhparameter
    extends asn1object
{
    asn1integer      p, g, l;

    public dhparameter(
        biginteger  p,
        biginteger  g,
        int         l)
    {
        this.p = new asn1integer(p);
        this.g = new asn1integer(g);

        if (l != 0)
        {
            this.l = new asn1integer(l);
        }
        else
        {
            this.l = null;
        }
    }

    public static dhparameter getinstance(
        object  obj)
    {
        if (obj instanceof dhparameter)
        {
            return (dhparameter)obj;
        }

        if (obj != null)
        {
            return new dhparameter(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private dhparameter(
        asn1sequence  seq)
    {
        enumeration     e = seq.getobjects();

        p = asn1integer.getinstance(e.nextelement());
        g = asn1integer.getinstance(e.nextelement());

        if (e.hasmoreelements())
        {
            l = (asn1integer)e.nextelement();
        }
        else
        {
            l = null;
        }
    }

    public biginteger getp()
    {
        return p.getpositivevalue();
    }

    public biginteger getg()
    {
        return g.getpositivevalue();
    }

    public biginteger getl()
    {
        if (l == null)
        {
            return null;
        }

        return l.getpositivevalue();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(p);
        v.add(g);

        if (this.getl() != null)
        {
            v.add(l);
        }

        return new dersequence(v);
    }
}
