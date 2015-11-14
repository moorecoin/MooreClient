package org.ripple.bouncycastle.pqc.math.ntru.euclid;

/**
 * extended euclidean algorithm in <code>int</code>s
 */
public class inteuclidean
{
    public int x, y, gcd;

    private inteuclidean()
    {
    }

    /**
     * runs the eea on two <code>int</code>s<br/>
     * implemented from pseudocode on <a href="http://en.wikipedia.org/wiki/extended_euclidean_algorithm">wikipedia</a>.
     *
     * @param a
     * @param b
     * @return a <code>inteuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and <code>gcd</code>
     */
    public static inteuclidean calculate(int a, int b)
    {
        int x = 0;
        int lastx = 1;
        int y = 1;
        int lasty = 0;
        while (b != 0)
        {
            int quotient = a / b;

            int temp = a;
            a = b;
            b = temp % b;

            temp = x;
            x = lastx - quotient * x;
            lastx = temp;

            temp = y;
            y = lasty - quotient * y;
            lasty = temp;
        }

        inteuclidean result = new inteuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}