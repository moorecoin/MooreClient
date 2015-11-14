package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

class referencemultiplier implements ecmultiplier
{
    /**
     * simple shift-and-add multiplication. serves as reference implementation
     * to verify (possibly faster) implementations in
     * {@link org.ripple.bouncycastle.math.ec.ecpoint ecpoint}.
     * 
     * @param p the point to multiply.
     * @param k the factor by which to multiply.
     * @return the result of the point multiplication <code>k * p</code>.
     */
    public ecpoint multiply(ecpoint p, biginteger k, precompinfo precompinfo)
    {
        ecpoint q = p.getcurve().getinfinity();
        int t = k.bitlength();
        for (int i = 0; i < t; i++)
        {
            if (k.testbit(i))
            {
                q = q.add(p);
            }
            p = p.twice();
        }
        return q;
    }
}
