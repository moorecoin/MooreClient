package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import java.math.bigdecimal;

/**
 * a polynomial with {@link bigdecimal} coefficients.
 * some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class bigdecimalpolynomial
{
    private static final bigdecimal zero = new bigdecimal("0");
    private static final bigdecimal one_half = new bigdecimal("0.5");

    bigdecimal[] coeffs;

    /**
     * constructs a new polynomial with <code>n</code> coefficients initialized to 0.
     *
     * @param n the number of coefficients
     */
    bigdecimalpolynomial(int n)
    {
        coeffs = new bigdecimal[n];
        for (int i = 0; i < n; i++)
        {
            coeffs[i] = zero;
        }
    }

    /**
     * constructs a new polynomial with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    bigdecimalpolynomial(bigdecimal[] coeffs)
    {
        this.coeffs = coeffs;
    }

    /**
     * constructs a <code>bigdecimalpolynomial</code> from a <code>bigintpolynomial</code>. the two polynomials are independent of each other.
     *
     * @param p the original polynomial
     */
    public bigdecimalpolynomial(bigintpolynomial p)
    {
        int n = p.coeffs.length;
        coeffs = new bigdecimal[n];
        for (int i = 0; i < n; i++)
        {
            coeffs[i] = new bigdecimal(p.coeffs[i]);
        }
    }

    /**
     * divides all coefficients by 2.
     */
    public void halve()
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].multiply(one_half);
        }
    }

    /**
     * multiplies the polynomial by another. does not change this polynomial
     * but returns the result as a new polynomial.
     *
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    public bigdecimalpolynomial mult(bigintpolynomial poly2)
    {
        return mult(new bigdecimalpolynomial(poly2));
    }

    /**
     * multiplies the polynomial by another, taking the indices mod n. does not
     * change this polynomial but returns the result as a new polynomial.
     *
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    public bigdecimalpolynomial mult(bigdecimalpolynomial poly2)
    {
        int n = coeffs.length;
        if (poly2.coeffs.length != n)
        {
            throw new illegalargumentexception("number of coefficients must be the same");
        }

        bigdecimalpolynomial c = multrecursive(poly2);

        if (c.coeffs.length > n)
        {
            for (int k = n; k < c.coeffs.length; k++)
            {
                c.coeffs[k - n] = c.coeffs[k - n].add(c.coeffs[k]);
            }
            c.coeffs = copyof(c.coeffs, n);
        }
        return c;
    }

    /**
     * karazuba multiplication
     */
    private bigdecimalpolynomial multrecursive(bigdecimalpolynomial poly2)
    {
        bigdecimal[] a = coeffs;
        bigdecimal[] b = poly2.coeffs;

        int n = poly2.coeffs.length;
        if (n <= 1)
        {
            bigdecimal[] c = coeffs.clone();
            for (int i = 0; i < coeffs.length; i++)
            {
                c[i] = c[i].multiply(poly2.coeffs[0]);
            }
            return new bigdecimalpolynomial(c);
        }
        else
        {
            int n1 = n / 2;

            bigdecimalpolynomial a1 = new bigdecimalpolynomial(copyof(a, n1));
            bigdecimalpolynomial a2 = new bigdecimalpolynomial(copyofrange(a, n1, n));
            bigdecimalpolynomial b1 = new bigdecimalpolynomial(copyof(b, n1));
            bigdecimalpolynomial b2 = new bigdecimalpolynomial(copyofrange(b, n1, n));

            bigdecimalpolynomial a = (bigdecimalpolynomial)a1.clone();
            a.add(a2);
            bigdecimalpolynomial b = (bigdecimalpolynomial)b1.clone();
            b.add(b2);

            bigdecimalpolynomial c1 = a1.multrecursive(b1);
            bigdecimalpolynomial c2 = a2.multrecursive(b2);
            bigdecimalpolynomial c3 = a.multrecursive(b);
            c3.sub(c1);
            c3.sub(c2);

            bigdecimalpolynomial c = new bigdecimalpolynomial(2 * n - 1);
            for (int i = 0; i < c1.coeffs.length; i++)
            {
                c.coeffs[i] = c1.coeffs[i];
            }
            for (int i = 0; i < c3.coeffs.length; i++)
            {
                c.coeffs[n1 + i] = c.coeffs[n1 + i].add(c3.coeffs[i]);
            }
            for (int i = 0; i < c2.coeffs.length; i++)
            {
                c.coeffs[2 * n1 + i] = c.coeffs[2 * n1 + i].add(c2.coeffs[i]);
            }
            return c;
        }
    }

    /**
     * adds another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    public void add(bigdecimalpolynomial b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            int n = coeffs.length;
            coeffs = copyof(coeffs, b.coeffs.length);
            for (int i = n; i < coeffs.length; i++)
            {
                coeffs[i] = zero;
            }
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].add(b.coeffs[i]);
        }
    }

    /**
     * subtracts another polynomial which can have a different number of coefficients.
     *
     * @param b
     */
    void sub(bigdecimalpolynomial b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            int n = coeffs.length;
            coeffs = copyof(coeffs, b.coeffs.length);
            for (int i = n; i < coeffs.length; i++)
            {
                coeffs[i] = zero;
            }
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].subtract(b.coeffs[i]);
        }
    }

    /**
     * rounds all coefficients to the nearest integer.
     *
     * @return a new polynomial with <code>biginteger</code> coefficients
     */
    public bigintpolynomial round()
    {
        int n = coeffs.length;
        bigintpolynomial p = new bigintpolynomial(n);
        for (int i = 0; i < n; i++)
        {
            p.coeffs[i] = coeffs[i].setscale(0, bigdecimal.round_half_even).tobiginteger();
        }
        return p;
    }

    /**
     * makes a copy of the polynomial that is independent of the original.
     */
    public object clone()
    {
        return new bigdecimalpolynomial(coeffs.clone());
    }

    private bigdecimal[] copyof(bigdecimal[] a, int length)
    {
        bigdecimal[] tmp = new bigdecimal[length];

        system.arraycopy(a, 0, tmp, 0, a.length < length ? a.length : length);

        return tmp;
    }

    private bigdecimal[] copyofrange(bigdecimal[] a, int from, int to)
    {
        int          newlength = to - from;
        bigdecimal[] tmp = new bigdecimal[to - from];

        system.arraycopy(a, from, tmp, 0, (a.length - from) < newlength ? (a.length - from) : newlength);

        return tmp;
    }

    public bigdecimal[] getcoeffs()
    {
        bigdecimal[] tmp = new bigdecimal[coeffs.length];

        system.arraycopy(coeffs, 0, tmp, 0, coeffs.length);

        return tmp;
    }

}
