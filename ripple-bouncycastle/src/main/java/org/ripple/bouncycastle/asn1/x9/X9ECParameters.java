package org.ripple.bouncycastle.asn1.x9;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * asn.1 def for elliptic-curve ecparameters structure. see
 * x9.62, for further details.
 */
public class x9ecparameters
    extends asn1object
    implements x9objectidentifiers
{
    private static final biginteger   one = biginteger.valueof(1);

    private x9fieldid           fieldid;
    private eccurve             curve;
    private ecpoint             g;
    private biginteger          n;
    private biginteger          h;
    private byte[]              seed;

    private x9ecparameters(
        asn1sequence  seq)
    {
        if (!(seq.getobjectat(0) instanceof asn1integer)
           || !((asn1integer)seq.getobjectat(0)).getvalue().equals(one))
        {
            throw new illegalargumentexception("bad version in x9ecparameters");
        }

        x9curve     x9c = new x9curve(
                        new x9fieldid((asn1sequence)seq.getobjectat(1)),
                        (asn1sequence)seq.getobjectat(2));

        this.curve = x9c.getcurve();
        this.g = new x9ecpoint(curve, (asn1octetstring)seq.getobjectat(3)).getpoint();
        this.n = ((asn1integer)seq.getobjectat(4)).getvalue();
        this.seed = x9c.getseed();

        if (seq.size() == 6)
        {
            this.h = ((asn1integer)seq.getobjectat(5)).getvalue();
        }
    }

    public static x9ecparameters getinstance(object obj)
    {
        if (obj instanceof x9ecparameters)
        {
            return (x9ecparameters)obj;
        }

        if (obj != null)
        {
            return new x9ecparameters(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public x9ecparameters(
        eccurve     curve,
        ecpoint     g,
        biginteger  n)
    {
        this(curve, g, n, one, null);
    }

    public x9ecparameters(
        eccurve     curve,
        ecpoint     g,
        biginteger  n,
        biginteger  h)
    {
        this(curve, g, n, h, null);
    }

    public x9ecparameters(
        eccurve     curve,
        ecpoint     g,
        biginteger  n,
        biginteger  h,
        byte[]      seed)
    {
        this.curve = curve;
        this.g = g;
        this.n = n;
        this.h = h;
        this.seed = seed;

        if (curve instanceof eccurve.fp)
        {
            this.fieldid = new x9fieldid(((eccurve.fp)curve).getq());
        }
        else
        {
            if (curve instanceof eccurve.f2m)
            {
                eccurve.f2m curvef2m = (eccurve.f2m)curve;
                this.fieldid = new x9fieldid(curvef2m.getm(), curvef2m.getk1(),
                    curvef2m.getk2(), curvef2m.getk3());
            }
        }
    }

    public eccurve getcurve()
    {
        return curve;
    }

    public ecpoint getg()
    {
        return g;
    }

    public biginteger getn()
    {
        return n;
    }

    public biginteger geth()
    {
        if (h == null)
        {
            return one;        // todo - this should be calculated, it will cause issues with custom curves.
        }

        return h;
    }

    public byte[] getseed()
    {
        return seed;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  ecparameters ::= sequence {
     *      version         integer { ecpver1(1) } (ecpver1),
     *      fieldid         fieldid {{fieldtypes}},
     *      curve           x9curve,
     *      base            x9ecpoint,
     *      order           integer,
     *      cofactor        integer optional
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(new asn1integer(1));
        v.add(fieldid);
        v.add(new x9curve(curve, seed));
        v.add(new x9ecpoint(g));
        v.add(new asn1integer(n));

        if (h != null)
        {
            v.add(new asn1integer(h));
        }

        return new dersequence(v);
    }
}
