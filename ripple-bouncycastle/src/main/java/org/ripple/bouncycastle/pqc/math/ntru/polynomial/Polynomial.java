package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

public interface polynomial
{

    /**
     * multiplies the polynomial by an <code>integerpolynomial</code>,
     * taking the indices mod <code>n</code>.
     *
     * @param poly2 a polynomial
     * @return the product of the two polynomials
     */
    integerpolynomial mult(integerpolynomial poly2);

    /**
     * multiplies the polynomial by an <code>integerpolynomial</code>,
     * taking the coefficient values mod <code>modulus</code> and the indices mod <code>n</code>.
     *
     * @param poly2   a polynomial
     * @param modulus a modulus to apply
     * @return the product of the two polynomials
     */
    integerpolynomial mult(integerpolynomial poly2, int modulus);

    /**
     * returns a polynomial that is equal to this polynomial (in the sense that {@link #mult(integerpolynomial, int)}
     * returns equal <code>integerpolynomial</code>s). the new polynomial is guaranteed to be independent of the original.
     *
     * @return a new <code>integerpolynomial</code>.
     */
    integerpolynomial tointegerpolynomial();

    /**
     * multiplies the polynomial by a <code>bigintpolynomial</code>, taking the indices mod n. does not
     * change this polynomial but returns the result as a new polynomial.<br/>
     * both polynomials must have the same number of coefficients.
     *
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    bigintpolynomial mult(bigintpolynomial poly2);
}
