package org.ripple.bouncycastle.jce.spec;

import java.math.biginteger;
import java.security.spec.keyspec;

/**
 * this class specifies a gost3410-94 private key with its associated parameters.
 */

public class gost3410privatekeyspec
    implements keyspec
{
    private biginteger x;
    private biginteger p;
    private biginteger q;
    private biginteger a;

    /**
     * creates a new gost3410privatekeyspec with the specified parameter values.
     *
     * @param x the private key.
     * @param p the prime.
     * @param q the sub-prime.
     * @param a the base.
     */
    public gost3410privatekeyspec(biginteger x, biginteger p, biginteger q,
         biginteger a)
    {
        this.x = x;
        this.p = p;
        this.q = q;
        this.a = a;
    }

    /**
     * returns the private key <code>x</code>.
     * @return the private key <code>x</code>.
     */
    public biginteger getx()
    {
        return this.x;
    }

    /**
     * returns the prime <code>p</code>.
     * @return the prime <code>p</code>.
     */
    public biginteger getp()
    {
        return this.p;
    }

    /**
     * returns the sub-prime <code>q</code>.
     * @return the sub-prime <code>q</code>.
     */
    public biginteger getq()
    {
        return this.q;
    }

    /**
     * returns the base <code>a</code>.
     * @return the base <code>a</code>.
     */
    public biginteger geta()
    {
        return this.a;
    }
}
