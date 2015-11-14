package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;
import java.security.spec.algorithmparameterspec;

public class elgamalparameterspec
    implements algorithmparameterspec
{
    private biginteger  p;
    private biginteger  g;

    /**
     * constructs a parameter set for diffie-hellman, using a prime modulus
     * <code>p</code> and a base generator <code>g</code>.
     * 
     * @param p the prime modulus
     * @param g the base generator
     */
    public elgamalparameterspec(
        biginteger  p,
        biginteger  g)
    {
        this.p = p;
        this.g = g;
    }

    /**
     * returns the prime modulus <code>p</code>.
     *
     * @return the prime modulus <code>p</code>
     */
    public biginteger getp()
    {
        return p;
    }

    /**
     * returns the base generator <code>g</code>.
     *
     * @return the base generator <code>g</code>
     */
    public biginteger getg()
    {
        return g;
    }
}
