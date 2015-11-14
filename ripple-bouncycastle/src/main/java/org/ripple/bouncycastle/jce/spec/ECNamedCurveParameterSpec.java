package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;

import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * specification signifying that the curve parameters can also be
 * refered to by name.
 * <p>
 * if you are using jdk 1.5 you should be looking at ecnamedcurvespec.
 */
public class ecnamedcurveparameterspec
    extends ecparameterspec
{
    private string  name;

    public ecnamedcurveparameterspec(
        string      name,
        eccurve     curve,
        ecpoint     g,
        biginteger  n)
    {
        super(curve, g, n);

        this.name = name;
    }

    public ecnamedcurveparameterspec(
        string      name,
        eccurve     curve,
        ecpoint     g,
        biginteger  n,
        biginteger  h)
    {
        super(curve, g, n, h);

        this.name = name;
    }

    public ecnamedcurveparameterspec(
        string      name,
        eccurve     curve,
        ecpoint     g,
        biginteger  n,
        biginteger  h,
        byte[]      seed)
    {
        super(curve, g, n, h, seed);

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
