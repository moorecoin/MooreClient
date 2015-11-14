package org.ripple.bouncycastle.jce.spec;

import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;

import java.math.biginteger;
import java.security.spec.algorithmparameterspec;

/**
 * basic domain parameters for an elliptic curve public or private key.
 */
public class ecparameterspec
    implements algorithmparameterspec
{
    private eccurve     curve;
    private byte[]      seed;
    private ecpoint     g;
    private biginteger  n;
    private biginteger  h;

    public ecparameterspec(
        eccurve     curve,
        ecpoint     g,
        biginteger  n)
    {
        this.curve = curve;
        this.g = g;
        this.n = n;
        this.h = biginteger.valueof(1);
        this.seed = null;
    }

    public ecparameterspec(
        eccurve     curve,
        ecpoint     g,
        biginteger  n,
        biginteger  h)
    {
        this.curve = curve;
        this.g = g;
        this.n = n;
        this.h = h;
        this.seed = null;
    }

    public ecparameterspec(
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

    /**
     * return the curve along which the base point lies.
     * @return the curve
     */
    public eccurve getcurve()
    {
        return curve;
    }

    /**
     * return the base point we are using for these domain parameters.
     * @return the base point.
     */
    public ecpoint getg()
    {
        return g;
    }

    /**
     * return the order n of g
     * @return the order
     */
    public biginteger getn()
    {
        return n;
    }

    /**
     * return the cofactor h to the order of g.
     * @return the cofactor
     */
    public biginteger geth()
    {
        return h;
    }

    /**
     * return the seed used to generate this curve (if available).
     * @return the random seed
     */
    public byte[] getseed()
    {
        return seed;
    }

    public boolean equals(object o)
    {
        if (!(o instanceof ecparameterspec))
        {
            return false;
        }

        ecparameterspec other = (ecparameterspec)o;

        return this.getcurve().equals(other.getcurve()) && this.getg().equals(other.getg());
    }

    public int hashcode()
    {
        return this.getcurve().hashcode() ^ this.getg().hashcode();
    }
}
