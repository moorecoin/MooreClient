package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

import org.ripple.bouncycastle.math.ec.ecconstants;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;
import org.ripple.bouncycastle.util.arrays;

public class ecdomainparameters
    implements ecconstants
{
    private eccurve     curve;
    private byte[]      seed;
    private ecpoint     g;
    private biginteger  n;
    private biginteger  h;

    public ecdomainparameters(
        eccurve     curve,
        ecpoint     g,
        biginteger  n)
    {
        this(curve, g, n, one, null);
    }

    public ecdomainparameters(
        eccurve     curve,
        ecpoint     g,
        biginteger  n,
        biginteger  h)
    {
        this(curve, g, n, h, null);
    }

    public ecdomainparameters(
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
        return h;
    }

    public byte[] getseed()
    {
        return arrays.clone(seed);
    }
}
