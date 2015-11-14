package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import java.math.biginteger;

/**
 * contains a resultant and a polynomial <code>rho</code> such that
 * <code>res = rho*this + t*(x^n-1) for some integer t</code>.
 *
 * @see integerpolynomial#resultant()
 * @see integerpolynomial#resultant(int)
 */
public class resultant
{
    /**
     * a polynomial such that <code>res = rho*this + t*(x^n-1) for some integer t</code>
     */
    public bigintpolynomial rho;
    /**
     * resultant of a polynomial with <code>x^n-1</code>
     */
    public biginteger res;

    resultant(bigintpolynomial rho, biginteger res)
    {
        this.rho = rho;
        this.res = res;
    }
}
