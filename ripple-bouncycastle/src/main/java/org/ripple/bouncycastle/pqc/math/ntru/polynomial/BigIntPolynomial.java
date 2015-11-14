package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import java.math.bigdecimal;
import java.math.biginteger;
import java.security.securerandom;
import java.util.arraylist;
import java.util.collections;
import java.util.list;

import org.ripple.bouncycastle.util.arrays;

/**
 * a polynomial with {@link biginteger} coefficients.<br/>
 * some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class bigintpolynomial
{
    private final static double log_10_2 = math.log10(2);

    biginteger[] coeffs;

    /**
     * constructs a new polynomial with <code>n</code> coefficients initialized to 0.
     *
     * @param n the number of coefficients
     */
    bigintpolynomial(int n)
    {
        coeffs = new biginteger[n];
        for (int i = 0; i < n; i++)
        {
            coeffs[i] = constants.bigint_zero;
        }
    }

    /**
     * constructs a new polynomial with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    bigintpolynomial(biginteger[] coeffs)
    {
        this.coeffs = coeffs;
    }

    /**
     * constructs a <code>bigintpolynomial</code> from a <code>integerpolynomial</code>. the two polynomials are
     * independent of each other.
     *
     * @param p the original polynomial
     */
    public bigintpolynomial(integerpolynomial p)
    {
        coeffs = new biginteger[p.coeffs.length];
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] = biginteger.valueof(p.coeffs[i]);
        }
    }

    /**
     * generates a random polynomial with <code>numones</code> coefficients equal to 1,
     * <code>numnegones</code> coefficients equal to -1, and the rest equal to 0.
     *
     * @param n          number of coefficients
     * @param numones    number of 1's
     * @param numnegones number of -1's
     * @return
     */
    static bigintpolynomial generaterandomsmall(int n, int numones, int numnegones)
    {
        list coeffs = new arraylist();
        for (int i = 0; i < numones; i++)
        {
            coeffs.add(constants.bigint_one);
        }
        for (int i = 0; i < numnegones; i++)
        {
            coeffs.add(biginteger.valueof(-1));
        }
        while (coeffs.size() < n)
        {
            coeffs.add(constants.bigint_zero);
        }
        collections.shuffle(coeffs, new securerandom());

        bigintpolynomial poly = new bigintpolynomial(n);
        for (int i = 0; i < coeffs.size(); i++)
        {
            poly.coeffs[i] = (biginteger)coeffs.get(i);
        }
        return poly;
    }

    /**
     * multiplies the polynomial by another, taking the indices mod n. does not
     * change this polynomial but returns the result as a new polynomial.<br/>
     * both polynomials must have the same number of coefficients.
     *
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    public bigintpolynomial mult(bigintpolynomial poly2)
    {
        int n = coeffs.length;
        if (poly2.coeffs.length != n)
        {
            throw new illegalargumentexception("number of coefficients must be the same");
        }

        bigintpolynomial c = multrecursive(poly2);

        if (c.coeffs.length > n)
        {
            for (int k = n; k < c.coeffs.length; k++)
            {
                c.coeffs[k - n] = c.coeffs[k - n].add(c.coeffs[k]);
            }
            c.coeffs = arrays.copyof(c.coeffs, n);
        }
        return c;
    }

    /**
     * karazuba multiplication
     */
    private bigintpolynomial multrecursive(bigintpolynomial poly2)
    {
        biginteger[] a = coeffs;
        biginteger[] b = poly2.coeffs;

        int n = poly2.coeffs.length;
        if (n <= 1)
        {
            biginteger[] c = arrays.clone(coeffs);
            for (int i = 0; i < coeffs.length; i++)
            {
                c[i] = c[i].multiply(poly2.coeffs[0]);
            }
            return new bigintpolynomial(c);
        }
        else
        {
            int n1 = n / 2;

            bigintpolynomial a1 = new bigintpolynomial(arrays.copyof(a, n1));
            bigintpolynomial a2 = new bigintpolynomial(arrays.copyofrange(a, n1, n));
            bigintpolynomial b1 = new bigintpolynomial(arrays.copyof(b, n1));
            bigintpolynomial b2 = new bigintpolynomial(arrays.copyofrange(b, n1, n));

            bigintpolynomial a = (bigintpolynomial)a1.clone();
            a.add(a2);
            bigintpolynomial b = (bigintpolynomial)b1.clone();
            b.add(b2);

            bigintpolynomial c1 = a1.multrecursive(b1);
            bigintpolynomial c2 = a2.multrecursive(b2);
            bigintpolynomial c3 = a.multrecursive(b);
            c3.sub(c1);
            c3.sub(c2);

            bigintpolynomial c = new bigintpolynomial(2 * n - 1);
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
     * adds another polynomial which can have a different number of coefficients,
     * and takes the coefficient values mod <code>modulus</code>.
     *
     * @param b another polynomial
     */
    void add(bigintpolynomial b, biginteger modulus)
    {
        add(b);
        mod(modulus);
    }

    /**
     * adds another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    public void add(bigintpolynomial b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            int n = coeffs.length;
            coeffs = arrays.copyof(coeffs, b.coeffs.length);
            for (int i = n; i < coeffs.length; i++)
            {
                coeffs[i] = constants.bigint_zero;
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
     * @param b another polynomial
     */
    public void sub(bigintpolynomial b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            int n = coeffs.length;
            coeffs = arrays.copyof(coeffs, b.coeffs.length);
            for (int i = n; i < coeffs.length; i++)
            {
                coeffs[i] = constants.bigint_zero;
            }
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].subtract(b.coeffs[i]);
        }
    }

    /**
     * multiplies each coefficient by a <code>biginteger</code>. does not return a new polynomial but modifies this polynomial.
     *
     * @param factor
     */
    public void mult(biginteger factor)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].multiply(factor);
        }
    }

    /**
     * multiplies each coefficient by a <code>int</code>. does not return a new polynomial but modifies this polynomial.
     *
     * @param factor
     */
    void mult(int factor)
    {
        mult(biginteger.valueof(factor));
    }

    /**
     * divides each coefficient by a <code>biginteger</code> and rounds the result to the nearest whole number.<br/>
     * does not return a new polynomial but modifies this polynomial.
     *
     * @param divisor the number to divide by
     */
    public void div(biginteger divisor)
    {
        biginteger d = divisor.add(constants.bigint_one).divide(biginteger.valueof(2));
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].compareto(constants.bigint_zero) > 0 ? coeffs[i].add(d) : coeffs[i].add(d.negate());
            coeffs[i] = coeffs[i].divide(divisor);
        }
    }

    /**
     * divides each coefficient by a <code>bigdecimal</code> and rounds the result to <code>decimalplaces</code> places.
     *
     * @param divisor       the number to divide by
     * @param decimalplaces the number of fractional digits to round the result to
     * @return a new <code>bigdecimalpolynomial</code>
     */
    public bigdecimalpolynomial div(bigdecimal divisor, int decimalplaces)
    {
        biginteger max = maxcoeffabs();
        int coefflength = (int)(max.bitlength() * log_10_2) + 1;
        // factor = 1/divisor
        bigdecimal factor = constants.bigdec_one.divide(divisor, coefflength + decimalplaces + 1, bigdecimal.round_half_even);

        // multiply each coefficient by factor
        bigdecimalpolynomial p = new bigdecimalpolynomial(coeffs.length);
        for (int i = 0; i < coeffs.length; i++)
        // multiply, then truncate after decimalplaces so subsequent operations aren't slowed down
        {
            p.coeffs[i] = new bigdecimal(coeffs[i]).multiply(factor).setscale(decimalplaces, bigdecimal.round_half_even);
        }

        return p;
    }

    /**
     * returns the base10 length of the largest coefficient.
     *
     * @return length of the longest coefficient
     */
    public int getmaxcoefflength()
    {
        return (int)(maxcoeffabs().bitlength() * log_10_2) + 1;
    }

    private biginteger maxcoeffabs()
    {
        biginteger max = coeffs[0].abs();
        for (int i = 1; i < coeffs.length; i++)
        {
            biginteger coeff = coeffs[i].abs();
            if (coeff.compareto(max) > 0)
            {
                max = coeff;
            }
        }
        return max;
    }

    /**
     * takes each coefficient modulo a number.
     *
     * @param modulus
     */
    public void mod(biginteger modulus)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].mod(modulus);
        }
    }

    /**
     * returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
     *
     * @return the sum of all coefficients
     */
    biginteger sumcoeffs()
    {
        biginteger sum = constants.bigint_zero;
        for (int i = 0; i < coeffs.length; i++)
        {
            sum = sum.add(coeffs[i]);
        }
        return sum;
    }

    /**
     * makes a copy of the polynomial that is independent of the original.
     */
    public object clone()
    {
        return new bigintpolynomial(coeffs.clone());
    }

    public int hashcode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + arrays.hashcode(coeffs);
        return result;
    }

    public boolean equals(object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (getclass() != obj.getclass())
        {
            return false;
        }
        bigintpolynomial other = (bigintpolynomial)obj;
        if (!arrays.areequal(coeffs, other.coeffs))
        {
            return false;
        }
        return true;
    }

    public biginteger[] getcoeffs()
    {
        return arrays.clone(coeffs);
    }
}
