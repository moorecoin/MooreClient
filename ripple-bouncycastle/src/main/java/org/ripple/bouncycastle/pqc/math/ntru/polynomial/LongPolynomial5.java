package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import org.ripple.bouncycastle.util.arrays;

/**
 * a polynomial class that combines five coefficients into one <code>long</code> value for
 * faster multiplication by a ternary polynomial.<br/>
 * coefficients can be between 0 and 2047 and are stored in bits 0..11, 12..23, ..., 48..59 of a <code>long</code> number.
 */
public class longpolynomial5
{
    private long[] coeffs;   // groups of 5 coefficients
    private int numcoeffs;

    /**
     * constructs a <code>longpolynomial5</code> from a <code>integerpolynomial</code>. the two polynomials are independent of each other.
     *
     * @param p the original polynomial. coefficients must be between 0 and 2047.
     */
    public longpolynomial5(integerpolynomial p)
    {
        numcoeffs = p.coeffs.length;

        coeffs = new long[(numcoeffs + 4) / 5];
        int cidx = 0;
        int shift = 0;
        for (int i = 0; i < numcoeffs; i++)
        {
            coeffs[cidx] |= ((long)p.coeffs[i]) << shift;
            shift += 12;
            if (shift >= 60)
            {
                shift = 0;
                cidx++;
            }
        }
    }

    private longpolynomial5(long[] coeffs, int numcoeffs)
    {
        this.coeffs = coeffs;
        this.numcoeffs = numcoeffs;
    }

    /**
     * multiplies the polynomial with a <code>ternarypolynomial</code>, taking the indices mod n and the values mod 2048.
     */
    public longpolynomial5 mult(ternarypolynomial poly2)
    {
        long[][] prod = new long[5][coeffs.length + (poly2.size() + 4) / 5 - 1];   // intermediate results, the subarrays are shifted by 0,...,4 coefficients

        // multiply ones
        int[] ones = poly2.getones();
        for (int idx = 0; idx != ones.length; idx++)
        {
            int pidx = ones[idx];
            int cidx = pidx / 5;
            int m = pidx - cidx * 5;   // m = pidx % 5
            for (int i = 0; i < coeffs.length; i++)
            {
                prod[m][cidx] = (prod[m][cidx] + coeffs[i]) & 0x7ff7ff7ff7ff7ffl;
                cidx++;
            }
        }

        // multiply negative ones
        int[] negones = poly2.getnegones();
        for (int idx = 0; idx != negones.length; idx++)
        {
            int pidx = negones[idx];
            int cidx = pidx / 5;
            int m = pidx - cidx * 5;   // m = pidx % 5
            for (int i = 0; i < coeffs.length; i++)
            {
                prod[m][cidx] = (0x800800800800800l + prod[m][cidx] - coeffs[i]) & 0x7ff7ff7ff7ff7ffl;
                cidx++;
            }
        }

        // combine shifted coefficients (5 arrays) into a single array of length prod[*].length+1
        long[] ccoeffs = arrays.copyof(prod[0], prod[0].length + 1);
        for (int m = 1; m <= 4; m++)
        {
            int shift = m * 12;
            int shift60 = 60 - shift;
            long mask = (1l << shift60) - 1;
            int plen = prod[m].length;
            for (int i = 0; i < plen; i++)
            {
                long upper, lower;
                upper = prod[m][i] >> shift60;
                lower = prod[m][i] & mask;

                ccoeffs[i] = (ccoeffs[i] + (lower << shift)) & 0x7ff7ff7ff7ff7ffl;
                int nextidx = i + 1;
                ccoeffs[nextidx] = (ccoeffs[nextidx] + upper) & 0x7ff7ff7ff7ff7ffl;
            }
        }

        // reduce indices of ccoeffs modulo numcoeffs
        int shift = 12 * (numcoeffs % 5);
        for (int cidx = coeffs.length - 1; cidx < ccoeffs.length; cidx++)
        {
            long icoeff;   // coefficient to shift into the [0..numcoeffs-1] range
            int newidx;
            if (cidx == coeffs.length - 1)
            {
                icoeff = numcoeffs == 5 ? 0 : ccoeffs[cidx] >> shift;
                newidx = 0;
            }
            else
            {
                icoeff = ccoeffs[cidx];
                newidx = cidx * 5 - numcoeffs;
            }

            int base = newidx / 5;
            int m = newidx - base * 5;   // m = newidx % 5
            long lower = icoeff << (12 * m);
            long upper = icoeff >> (12 * (5 - m));
            ccoeffs[base] = (ccoeffs[base] + lower) & 0x7ff7ff7ff7ff7ffl;
            int base1 = base + 1;
            if (base1 < coeffs.length)
            {
                ccoeffs[base1] = (ccoeffs[base1] + upper) & 0x7ff7ff7ff7ff7ffl;
            }
        }

        return new longpolynomial5(ccoeffs, numcoeffs);
    }

    public integerpolynomial tointegerpolynomial()
    {
        int[] intcoeffs = new int[numcoeffs];
        int cidx = 0;
        int shift = 0;
        for (int i = 0; i < numcoeffs; i++)
        {
            intcoeffs[i] = (int)((coeffs[cidx] >> shift) & 2047);
            shift += 12;
            if (shift >= 60)
            {
                shift = 0;
                cidx++;
            }
        }
        return new integerpolynomial(intcoeffs);
    }
}
