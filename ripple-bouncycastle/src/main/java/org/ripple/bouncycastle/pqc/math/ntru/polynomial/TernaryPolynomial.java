package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

/**
 * a polynomial whose coefficients are all equal to -1, 0, or 1
 */
public interface ternarypolynomial
    extends polynomial
{

    /**
     * multiplies the polynomial by an <code>integerpolynomial</code>, taking the indices mod n
     */
    integerpolynomial mult(integerpolynomial poly2);

    int[] getones();

    int[] getnegones();

    /**
     * returns the maximum number of coefficients the polynomial can have
     */
    int size();

    void clear();
}
