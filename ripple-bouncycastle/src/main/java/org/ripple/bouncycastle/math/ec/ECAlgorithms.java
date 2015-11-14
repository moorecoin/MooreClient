package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

public class ecalgorithms
{
    public static ecpoint sumoftwomultiplies(ecpoint p, biginteger a,
        ecpoint q, biginteger b)
    {
        eccurve c = p.getcurve();
        if (!c.equals(q.getcurve()))
        {
            throw new illegalargumentexception("p and q must be on same curve");
        }

        // point multiplication for koblitz curves (using wtnaf) beats shamir's trick
        if (c instanceof eccurve.f2m)
        {
            eccurve.f2m f2mcurve = (eccurve.f2m)c;
            if (f2mcurve.iskoblitz())
            {
                return p.multiply(a).add(q.multiply(b));
            }
        }

        return implshamirstrick(p, a, q, b);
    }

    /*
     * "shamir's trick", originally due to e. g. straus
     * (addition chains of vectors. american mathematical monthly,
     * 71(7):806-808, aug./sept. 1964)
     * <pre>
     * input: the points p, q, scalar k = (km?, ... , k1, k0)
     * and scalar l = (lm?, ... , l1, l0).
     * output: r = k * p + l * q.
     * 1: z <- p + q
     * 2: r <- o
     * 3: for i from m-1 down to 0 do
     * 4:        r <- r + r        {point doubling}
     * 5:        if (ki = 1) and (li = 0) then r <- r + p end if
     * 6:        if (ki = 0) and (li = 1) then r <- r + q end if
     * 7:        if (ki = 1) and (li = 1) then r <- r + z end if
     * 8: end for
     * 9: return r
     * </pre>
     */
    public static ecpoint shamirstrick(ecpoint p, biginteger k,
        ecpoint q, biginteger l)
    {
        if (!p.getcurve().equals(q.getcurve()))
        {
            throw new illegalargumentexception("p and q must be on same curve");
        }

        return implshamirstrick(p, k, q, l);
    }

    private static ecpoint implshamirstrick(ecpoint p, biginteger k,
        ecpoint q, biginteger l)
    {
        int m = math.max(k.bitlength(), l.bitlength());
        ecpoint z = p.add(q);
        ecpoint r = p.getcurve().getinfinity();

        for (int i = m - 1; i >= 0; --i)
        {
            r = r.twice();

            if (k.testbit(i))
            {
                if (l.testbit(i))
                {
                    r = r.add(z);
                }
                else
                {
                    r = r.add(p);
                }
            }
            else
            {
                if (l.testbit(i))
                {
                    r = r.add(q);
                }
            }
        }

        return r;
    }
}
