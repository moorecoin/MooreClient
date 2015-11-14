package org.ripple.bouncycastle.asn1.oiw;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class elgamalparameter
    extends asn1object
{
    asn1integer      p, g;

    public elgamalparameter(
        biginteger  p,
        biginteger  g)
    {
        this.p = new asn1integer(p);
        this.g = new asn1integer(g);
    }

    public elgamalparameter(
        asn1sequence  seq)
    {
        enumeration     e = seq.getobjects();

        p = (asn1integer)e.nextelement();
        g = (asn1integer)e.nextelement();
    }

    public biginteger getp()
    {
        return p.getpositivevalue();
    }

    public biginteger getg()
    {
        return g.getpositivevalue();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(p);
        v.add(g);

        return new dersequence(v);
    }
}
