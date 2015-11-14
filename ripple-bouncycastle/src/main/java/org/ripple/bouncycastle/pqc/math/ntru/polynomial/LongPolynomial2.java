package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import org.ripple.bouncycastle.util.arrays;

/**
 * a polynomial class that combines two coefficients into one <code>long</code> value for
 * faster multiplication in 64 bit environments.<br/>
 * coefficients can be between 0 and 2047 and are stored in pairs in the bits 0..10 and 24..34 of a <code>long</code> number.
 */
public class longpolynomial2
{
    private long[] coeffs;   // each representing two coefficients in the original integerpolynomial
    private int numcoeffs;

    /**
     * constructs a <code>longpolynomial2</code> from a <code>integerpolynomial</code>. the two polynomials are independent of each other.
     *
     * @param p the original polynomial. coefficients must be between 0 and 2047.
     */
    public longpolynomial2(integerpolynomial p)
    {
        numcoeffs = p.coeffs.length;
        coeffs = new long[(numcoeffs + 1) / 2];
        int idx = 0;
        for (int pidx = 0; pidx < numcoeffs; )
        {
            int c0 = p.coeffs[pidx++];
            while (c0 < 0)
            {
                c0 += 2048;
            }
            long c1 = pidx < numcoeffs ? p.coeffs[pidx++] : 0;
            while (c1 < 0)
            {
                c1 += 2048;
            }
            coeffs[idx] = c0 + (c1 << 24);
            idx++;
        }
    }

    private longpolynomial2(long[] coeffs)
    {
        this.coeffs = coeffs;
    }

    private longpolynomial2(int n)
    {
        coeffs = new long[n];
    }

    /**
     * multiplies the polynomial with another, taking the indices mod n and the values mod 2048.
     */
    public longpolynomial2 mult(longpolynomial2 poly2)
    {
        int n = coeffs.length;
        if (poly2.coeffs.length != n || numcoeffs != poly2.numcoeffs)
        {
            throw new illegalargumentexception("number of coefficients must be the same");
        }

        longpolynomial2 c = multrecursive(poly2);

        if (c.coeffs.length > n)
        {
            if (numcoeffs % 2 == 0)
            {
                for (int k = n; k < c.coeffs.length; k++)
                {
                    c.coeffs[k - n] = (c.coeffs[k - n] + c.coeffs[k]) & 0x7ff0007ffl;
                }
                c.coeffs = arrays.copyof(c.coeffs, n);
            }
            else
            {
                for (int k = n; k < c.coeffs.length; k++)
                {
                    c.coeffs[k - n] = c.coeffs[k - n] + (c.coeffs[k - 1] >> 24);
                    c.coeffs[k - n] = c.coeffs[k - n] + ((c.coeffs[k] & 2047) << 24);
                    c.coeffs[k - n] &= 0x7ff0007ffl;
                }
                c.coeffs = arrays.copyof(c.coeffs, n);
                c.coeffs[c.coeffs.length - 1] &= 2047;
            }
        }

        c = new longpolynomial2(c.coeffs);
        c.numcoeffs = numcoeffs;
        return c;
    }

    public integerpolynomial tointegerpolynomial()
    {
        int[] intcoeffs = new int[numcoeffs];
        int uidx = 0;
        for (int i = 0; i < coeffs.length; i++)
        {
            intcoeffs[uidx++] = (int)(coeffs[i] & 2047);
            if (uidx < numcoeffs)
            {
                intcoeffs[uidx++] = (int)((coeffs[i] >> 24) & 2047);
            }
        }
        return new integerpolynomial(intcoeffs);
    }

    /**
     * karazuba multiplication
     */
    private longpolynomial2 multrecursive(longpolynomial2 poly2)
    {
        long[] a = coeffs;
        long[] b = poly2.coeffs;

        int n = poly2.coeffs.length;
        if (n <= 32)
        {
            int cn = 2 * n;
            longpolynomial2 c = new longpolynomial2(new long[cn]);
            for (int k = 0; k < cn; k++)
            {
                for (int i = math.max(0, k - n + 1); i <= math.min(k, n - 1); i++)
                {
                    long c0 = a[k - i] * b[i];
                    long cu = c0 & 0x7ff000000l + (c0 & 2047);
                    long co = (c0 >>> 48) & 2047;

                    c.coeffs[k] = (c.coeffs[k] + cu) & 0x7ff0007ffl;
                    c.coeffs[k + 1] = (c.coeffs[k + 1] + co) & 0x7ff0007ffl;
                }
            }
            return c;
        }
        else
        {
            int n1 = n / 2;

            longpolynomial2 a1 = new longpolynomial2(arrays.copyof(a, n1));
            longpolynomial2 a2 = new longpolynomial2(arrays.copyofrange(a, n1, n));
            longpolynomial2 b1 = new longpolynomial2(arrays.copyof(b, n1));
            longpolynomial2 b2 = new longpolynomial2(arrays.copyofrange(b, n1, n));

            longpolynomial2 a = (longpolynomial2)a1.clone();
            a.add(a2);
            longpolynomial2 b = (longpolynomial2)b1.clone();
            b.add(b2);

            longpolynomial2 c1 = a1.multrecursive(b1);
            longpolynomial2 c2 = a2.multrecursive(b2);
            longpolynomial2 c3 = a.multrecursive(b);
            c3.sub(c1);
            c3.sub(c2);

            longpolynomial2 c = new longpolynomial2(2 * n);
            for (int i = 0; i < c1.coeffs.length; i++)
            {
                c.coeffs[i] = c1.coeffs[i] & 0x7ff0007ffl;
            }
            for (int i = 0; i < c3.coeffs.length; i++)
            {
                c.coeffs[n1 + i] = (c.coeffs[n1 + i] + c3.coeffs[i]) & 0x7ff0007ffl;
            }
            for (int i = 0; i < c2.coeffs.length; i++)
            {
                c.coeffs[2 * n1 + i] = (c.coeffs[2 * n1 + i] + c2.coeffs[i]) & 0x7ff0007ffl;
            }
            return c;
        }
    }

    /**
     * adds another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    private void add(longpolynomial2 b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            coeffs = arrays.copyof(coeffs, b.coeffs.length);
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] = (coeffs[i] + b.coeffs[i]) & 0x7ff0007ffl;
        }
    }

    /**
     * subtracts another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    private void sub(longpolynomial2 b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            coeffs = arrays.copyof(coeffs, b.coeffs.length);
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] = (0x0800000800000l + coeffs[i] - b.coeffs[i]) & 0x7ff0007ffl;
        }
    }

    /**
     * subtracts another polynomial which must have the same number of coefficients,
     * and applies an and mask to the upper and lower halves of each coefficients.
     *
     * @param b    another polynomial
     * @param mask a bit mask less than 2048 to apply to each 11-bit coefficient
     */
    public void suband(longpolynomial2 b, int mask)
    {
        long longmask = (((long)mask) << 24) + mask;
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] = (0x0800000800000l + coeffs[i] - b.coeffs[i]) & longmask;
        }
    }

    /**
     * multiplies this polynomial by 2 and applies an and mask to the upper and
     * lower halves of each coefficients.
     *
     * @param mask a bit mask less than 2048 to apply to each 11-bit coefficient
     */
    public void mult2and(int mask)
    {
        long longmask = (((long)mask) << 24) + mask;
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] = (coeffs[i] << 1) & longmask;
        }
    }

    public object clone()
    {
        longpolynomial2 p = new longpolynomial2(coeffs.clone());
        p.numcoeffs = numcoeffs;
        return p;
    }

    public boolean equals(object obj)
    {
        if (obj instanceof longpolynomial2)
        {
            return arrays.areequal(coeffs, ((longpolynomial2)obj).coeffs);
        }
        else
        {
            return false;
        }
    }
}
