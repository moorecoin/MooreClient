package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.biginteger;
import java.security.spec.ecfield;
import java.security.spec.ecfieldf2m;
import java.security.spec.ecfieldfp;
import java.security.spec.ecparameterspec;
import java.security.spec.ecpoint;
import java.security.spec.ellipticcurve;

import org.ripple.bouncycastle.jce.spec.ecnamedcurveparameterspec;
import org.ripple.bouncycastle.jce.spec.ecnamedcurvespec;
import org.ripple.bouncycastle.math.ec.eccurve;

public class ec5util
{
    public static ellipticcurve convertcurve(
        eccurve curve, 
        byte[]  seed)
    {
        // todo: the sun ec implementation doesn't currently handle the seed properly
        // so at the moment it's set to null. should probably look at making this configurable
        if (curve instanceof eccurve.fp)
        {
            return new ellipticcurve(new ecfieldfp(((eccurve.fp)curve).getq()), curve.geta().tobiginteger(), curve.getb().tobiginteger(), null);
        }
        else
        {
            eccurve.f2m curvef2m = (eccurve.f2m)curve;
            int ks[];
            
            if (curvef2m.istrinomial())
            {
                ks = new int[] { curvef2m.getk1() };
                
                return new ellipticcurve(new ecfieldf2m(curvef2m.getm(), ks), curve.geta().tobiginteger(), curve.getb().tobiginteger(), null);
            }
            else
            {
                ks = new int[] { curvef2m.getk3(), curvef2m.getk2(), curvef2m.getk1() };
                
                return new ellipticcurve(new ecfieldf2m(curvef2m.getm(), ks), curve.geta().tobiginteger(), curve.getb().tobiginteger(), null);
            } 
        }
    }

    public static eccurve convertcurve(
        ellipticcurve ec)
    {
        ecfield field = ec.getfield();
        biginteger a = ec.geta();
        biginteger b = ec.getb();

        if (field instanceof ecfieldfp)
        {
            return new eccurve.fp(((ecfieldfp)field).getp(), a, b);
        }
        else
        {
            ecfieldf2m fieldf2m = (ecfieldf2m)field;
            int m = fieldf2m.getm();
            int ks[] = ecutil.convertmidterms(fieldf2m.getmidtermsofreductionpolynomial());
            return new eccurve.f2m(m, ks[0], ks[1], ks[2], a, b); 
        }
    }

    public static ecparameterspec convertspec(
        ellipticcurve ellipticcurve,
        org.ripple.bouncycastle.jce.spec.ecparameterspec spec)
    {
        if (spec instanceof ecnamedcurveparameterspec)
        {
            return new ecnamedcurvespec(
                ((ecnamedcurveparameterspec)spec).getname(),
                ellipticcurve,
                new ecpoint(
                    spec.getg().getx().tobiginteger(),
                    spec.getg().gety().tobiginteger()),
                spec.getn(),
                spec.geth());
        }
        else
        {
            return new ecparameterspec(
                ellipticcurve,
                new ecpoint(
                    spec.getg().getx().tobiginteger(),
                    spec.getg().gety().tobiginteger()),
                spec.getn(),
                spec.geth().intvalue());
        }
    }

    public static org.ripple.bouncycastle.jce.spec.ecparameterspec convertspec(
        ecparameterspec ecspec,
        boolean withcompression)
    {
        eccurve curve = convertcurve(ecspec.getcurve());

        return new org.ripple.bouncycastle.jce.spec.ecparameterspec(
            curve,
            convertpoint(curve, ecspec.getgenerator(), withcompression),
            ecspec.getorder(),
            biginteger.valueof(ecspec.getcofactor()),
            ecspec.getcurve().getseed());
    }

    public static org.ripple.bouncycastle.math.ec.ecpoint convertpoint(
        ecparameterspec ecspec,
        ecpoint point,
        boolean withcompression)
    {
        return convertpoint(convertcurve(ecspec.getcurve()), point, withcompression);
    }

    public static org.ripple.bouncycastle.math.ec.ecpoint convertpoint(
        eccurve curve,
        ecpoint point,
        boolean withcompression)
    {
        return curve.createpoint(point.getaffinex(), point.getaffiney(), withcompression);
    }
}
