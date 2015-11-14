package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import java.security.securerandom;

import org.ripple.bouncycastle.pqc.math.ntru.util.util;
import org.ripple.bouncycastle.util.arrays;

/**
 * a <code>ternarypolynomial</code> with a "high" number of nonzero coefficients.
 */
public class denseternarypolynomial
    extends integerpolynomial
    implements ternarypolynomial
{

    /**
     * constructs a new <code>denseternarypolynomial</code> with <code>n</code> coefficients.
     *
     * @param n the number of coefficients
     */
    denseternarypolynomial(int n)
    {
        super(n);
        checkternarity();
    }

    /**
     * constructs a <code>denseternarypolynomial</code> from a <code>integerpolynomial</code>. the two polynomials are
     * independent of each other.
     *
     * @param intpoly the original polynomial
     */
    public denseternarypolynomial(integerpolynomial intpoly)
    {
        this(intpoly.coeffs);
    }

    /**
     * constructs a new <code>denseternarypolynomial</code> with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    public denseternarypolynomial(int[] coeffs)
    {
        super(coeffs);
        checkternarity();
    }

    private void checkternarity()
    {
        for (int i = 0; i != coeffs.length; i++)
        {
            int c = coeffs[i];
            if (c < -1 || c > 1)
            {
                throw new illegalstateexception("illegal value: " + c + ", must be one of {-1, 0, 1}");
            }
        }
    }

    /**
     * generates a random polynomial with <code>numones</code> coefficients equal to 1,
     * <code>numnegones</code> coefficients equal to -1, and the rest equal to 0.
     *
     * @param n          number of coefficients
     * @param numones    number of 1's
     * @param numnegones number of -1's
     */
    public static denseternarypolynomial generaterandom(int n, int numones, int numnegones, securerandom random)
    {
        int[] coeffs = util.generaterandomternary(n, numones, numnegones, random);
        return new denseternarypolynomial(coeffs);
    }

    /**
     * generates a polynomial with coefficients randomly selected from <code>{-1, 0, 1}</code>.
     *
     * @param n number of coefficients
     */
    public static denseternarypolynomial generaterandom(int n, securerandom random)
    {
        denseternarypolynomial poly = new denseternarypolynomial(n);
        for (int i = 0; i < n; i++)
        {
            poly.coeffs[i] = random.nextint(3) - 1;
        }
        return poly;
    }

    public integerpolynomial mult(integerpolynomial poly2, int modulus)
    {
        // even on 32-bit systems, longpolynomial5 multiplies faster than integerpolynomial
        if (modulus == 2048)
        {
            integerpolynomial poly2pos = (integerpolynomial)poly2.clone();
            poly2pos.modpositive(2048);
            longpolynomial5 poly5 = new longpolynomial5(poly2pos);
            return poly5.mult(this).tointegerpolynomial();
        }
        else
        {
            return super.mult(poly2, modulus);
        }
    }

    public int[] getones()
    {
        int n = coeffs.length;
        int[] ones = new int[n];
        int onesidx = 0;
        for (int i = 0; i < n; i++)
        {
            int c = coeffs[i];
            if (c == 1)
            {
                ones[onesidx++] = i;
            }
        }
        return arrays.copyof(ones, onesidx);
    }

    public int[] getnegones()
    {
        int n = coeffs.length;
        int[] negones = new int[n];
        int negonesidx = 0;
        for (int i = 0; i < n; i++)
        {
            int c = coeffs[i];
            if (c == -1)
            {
                negones[negonesidx++] = i;
            }
        }
        return arrays.copyof(negones, negonesidx);
    }

    public int size()
    {
        return coeffs.length;
    }
}
