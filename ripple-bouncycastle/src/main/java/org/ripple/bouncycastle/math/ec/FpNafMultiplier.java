package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

/**
 * class implementing the naf (non-adjacent form) multiplication algorithm.
 */
class fpnafmultiplier implements ecmultiplier
{
    /**
     * d.3.2 pg 101
     * @see org.ripple.bouncycastle.math.ec.ecmultiplier#multiply(org.ripple.bouncycastle.math.ec.ecpoint, java.math.biginteger)
     */
    public ecpoint multiply(ecpoint p, biginteger k, precompinfo precompinfo)
    {
        // todo probably should try to add this
        // biginteger e = k.mod(n); // n == order of p
        biginteger e = k;
        biginteger h = e.multiply(biginteger.valueof(3));

        ecpoint neg = p.negate();
        ecpoint r = p;

        for (int i = h.bitlength() - 2; i > 0; --i)
        {             
            r = r.twice();

            boolean hbit = h.testbit(i);
            boolean ebit = e.testbit(i);

            if (hbit != ebit)
            {
                r = r.add(hbit ? p : neg);
            }
        }

        return r;
    }
}
