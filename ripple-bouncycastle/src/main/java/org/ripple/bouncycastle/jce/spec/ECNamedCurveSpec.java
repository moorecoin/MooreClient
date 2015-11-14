package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;
import java.security.spec.ecfieldf2m;
import java.security.spec.ecfieldfp;
import java.security.spec.ecpoint;
import java.security.spec.ellipticcurve;

import org.ripple.bouncycastle.math.ec.eccurve;

/**
 * specification signifying that the curve parameters can also be
 * referred to by name.
 */
public class ecnamedcurvespec
    extends java.security.spec.ecparameterspec
{
    private string  name;

    private static ellipticcurve convertcurve(
        eccurve  curve,
        byte[]   seed)
    {
        if (curve instanceof eccurve.fp)
        {
            return new ellipticcurve(new ecfieldfp(((eccurve.fp)curve).getq()), curve.geta().tobiginteger(), curve.getb().tobiginteger(), seed);
        }
        else
        {
            eccurve.f2m curvef2m = (eccurve.f2m)curve;
            int ks[];
            
            if (curvef2m.istrinomial())
            {
                ks = new int[] { curvef2m.getk1() };
                
                return new ellipticcurve(new ecfieldf2m(curvef2m.getm(), ks), curve.geta().tobiginteger(), curve.getb().tobiginteger(), seed);
            }
            else
            {
                ks = new int[] { curvef2m.getk3(), curvef2m.getk2(), curvef2m.getk1() };

                return new ellipticcurve(new ecfieldf2m(curvef2m.getm(), ks), curve.geta().tobiginteger(), curve.getb().tobiginteger(), seed);
            } 
        }

    }
    
    private static ecpoint convertpoint(
        org.ripple.bouncycastle.math.ec.ecpoint  g)
    {
        return new ecpoint(g.getx().tobiginteger(), g.gety().tobiginteger());
    }
    
    public ecnamedcurvespec(
        string                              name,
        eccurve                             curve,
        org.ripple.bouncycastle.math.ec.ecpoint    g,
        biginteger                          n)
    {
        super(convertcurve(curve, null), convertpoint(g), n, 1);

        this.name = name;
    }

    public ecnamedcurvespec(
        string          name,
        ellipticcurve   curve,
        ecpoint         g,
        biginteger      n)
    {
        super(curve, g, n, 1);

        this.name = name;
    }
    
    public ecnamedcurvespec(
        string                              name,
        eccurve                             curve,
        org.ripple.bouncycastle.math.ec.ecpoint    g,
        biginteger                          n,
        biginteger                          h)
    {
        super(convertcurve(curve, null), convertpoint(g), n, h.intvalue());

        this.name = name;
    }

    public ecnamedcurvespec(
        string          name,
        ellipticcurve   curve,
        ecpoint         g,
        biginteger      n,
        biginteger      h)
    {
        super(curve, g, n, h.intvalue());

        this.name = name;
    }
    
    public ecnamedcurvespec(
        string                              name,
        eccurve                             curve,
        org.ripple.bouncycastle.math.ec.ecpoint    g,
        biginteger                          n,
        biginteger                          h,
        byte[]                              seed)
    {
        super(convertcurve(curve, seed), convertpoint(g), n, h.intvalue());
        
        this.name = name;
    }

    /**
     * return the name of the curve the ec domain parameters belong to.
     */
    public string getname()
    {
        return name;
    }
}
