package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;
import java.security.spec.keyspec;

/**
 * this class specifies a gost3410-94 public key with its associated parameters.
 */

public class gost3410publickeyspec
    implements keyspec
{

    private biginteger y;
    private biginteger p;
    private biginteger q;
    private biginteger a;

    /**
     * creates a new gost3410publickeyspec with the specified parameter values.
     *
     * @param y the public key.
     * @param p the prime.
     * @param q the sub-prime.
     * @param a the base.
     */
    public gost3410publickeyspec(
        biginteger y,
        biginteger p,
        biginteger q,
        biginteger a)
    {
        this.y = y;
        this.p = p;
        this.q = q;
        this.a = a;
    }

    /**
     * returns the public key <code>y</code>.
     *
     * @return the public key <code>y</code>.
     */
    public biginteger gety()
    {
        return this.y;
    }

    /**
     * returns the prime <code>p</code>.
     *
     * @return the prime <code>p</code>.
     */
    public biginteger getp()
    {
        return this.p;
    }

    /**
     * returns the sub-prime <code>q</code>.
     *
     * @return the sub-prime <code>q</code>.
     */
    public biginteger getq()
    {
        return this.q;
    }

    /**
     * returns the base <code>g</code>.
     *
     * @return the base <code>g</code>.
     */
    public biginteger geta()
    {
        return this.a;
    }
}
