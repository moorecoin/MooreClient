package org.ripple.bouncycastle.pqc.math.ntru.euclid;

import java.math.biginteger;

/**
 * extended euclidean algorithm in <code>biginteger</code>s
 */
public class biginteuclidean
{
    public biginteger x, y, gcd;

    private biginteuclidean()
    {
    }

    /**
     * runs the eea on two <code>biginteger</code>s<br/>
     * implemented from pseudocode on <a href="http://en.wikipedia.org/wiki/extended_euclidean_algorithm">wikipedia</a>.
     *
     * @param a
     * @param b
     * @return a <code>biginteuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and <code>gcd</code>
     */
    public static biginteuclidean calculate(biginteger a, biginteger b)
    {
        biginteger x = biginteger.zero;
        biginteger lastx = biginteger.one;
        biginteger y = biginteger.one;
        biginteger lasty = biginteger.zero;
        while (!b.equals(biginteger.zero))
        {
            biginteger[] quotientandremainder = a.divideandremainder(b);
            biginteger quotient = quotientandremainder[0];

            biginteger temp = a;
            a = b;
            b = quotientandremainder[1];

            temp = x;
            x = lastx.subtract(quotient.multiply(x));
            lastx = temp;

            temp = y;
            y = lasty.subtract(quotient.multiply(y));
            lasty = temp;
        }

        biginteuclidean result = new biginteuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}