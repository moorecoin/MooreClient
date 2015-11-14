package org.ripple.bouncycastle.pqc.math.linearalgebra;

/**
 * this class describes operations with polynomials over finite field gf(2), i e
 * polynomial ring r = gf(2)[x]. all operations are defined only for polynomials
 * with degree <=32. for the polynomial representation the map f: r->z,
 * poly(x)->poly(2) is used, where integers have the binary representation. for
 * example: x^7+x^3+x+1 -> (00...0010001011)=139 also for polynomials type
 * integer is used.
 *
 * @see gf2mfield
 */
public final class polynomialringgf2
{

    /**
     * default constructor (private).
     */
    private polynomialringgf2()
    {
        // empty
    }

    /**
     * return sum of two polyomials
     *
     * @param p polynomial
     * @param q polynomial
     * @return p+q
     */

    public static int add(int p, int q)
    {
        return p ^ q;
    }

    /**
     * return product of two polynomials
     *
     * @param p polynomial
     * @param q polynomial
     * @return p*q
     */

    public static long multiply(int p, int q)
    {
        long result = 0;
        if (q != 0)
        {
            long q1 = q & 0x00000000ffffffffl;

            while (p != 0)
            {
                byte b = (byte)(p & 0x01);
                if (b == 1)
                {
                    result ^= q1;
                }
                p >>>= 1;
                q1 <<= 1;

            }
        }
        return result;
    }

    /**
     * compute the product of two polynomials modulo a third polynomial.
     *
     * @param a the first polynomial
     * @param b the second polynomial
     * @param r the reduction polynomial
     * @return <tt>a * b mod r</tt>
     */
    public static int modmultiply(int a, int b, int r)
    {
        int result = 0;
        int p = remainder(a, r);
        int q = remainder(b, r);
        if (q != 0)
        {
            int d = 1 << degree(r);

            while (p != 0)
            {
                byte pmod2 = (byte)(p & 0x01);
                if (pmod2 == 1)
                {
                    result ^= q;
                }
                p >>>= 1;
                q <<= 1;
                if (q >= d)
                {
                    q ^= r;
                }
            }
        }
        return result;
    }

    /**
     * return the degree of a polynomial
     *
     * @param p polynomial p
     * @return degree(p)
     */

    public static int degree(int p)
    {
        int result = -1;
        while (p != 0)
        {
            result++;
            p >>>= 1;
        }
        return result;
    }

    /**
     * return the degree of a polynomial
     *
     * @param p polynomial p
     * @return degree(p)
     */

    public static int degree(long p)
    {
        int result = 0;
        while (p != 0)
        {
            result++;
            p >>>= 1;
        }
        return result - 1;
    }

    /**
     * return the remainder of a polynomial division of two polynomials.
     *
     * @param p dividend
     * @param q divisor
     * @return <tt>p mod q</tt>
     */
    public static int remainder(int p, int q)
    {
        int result = p;

        if (q == 0)
        {
            system.err.println("error: to be divided by 0");
            return 0;
        }

        while (degree(result) >= degree(q))
        {
            result ^= q << (degree(result) - degree(q));
        }

        return result;
    }

    /**
     * return the rest of devision two polynomials
     *
     * @param p polinomial
     * @param q polinomial
     * @return p mod q
     */

    public static int rest(long p, int q)
    {
        long p1 = p;
        if (q == 0)
        {
            system.err.println("error: to be divided by 0");
            return 0;
        }
        long q1 = q & 0x00000000ffffffffl;
        while ((p1 >>> 32) != 0)
        {
            p1 ^= q1 << (degree(p1) - degree(q1));
        }

        int result = (int)(p1 & 0xffffffff);
        while (degree(result) >= degree(q))
        {
            result ^= q << (degree(result) - degree(q));
        }

        return result;
    }

    /**
     * return the greatest common divisor of two polynomials
     *
     * @param p polinomial
     * @param q polinomial
     * @return gcd(p, q)
     */

    public static int gcd(int p, int q)
    {
        int a, b, c;
        a = p;
        b = q;
        while (b != 0)
        {
            c = remainder(a, b);
            a = b;
            b = c;

        }
        return a;
    }

    /**
     * checking polynomial for irreducibility
     *
     * @param p polinomial
     * @return true if p is irreducible and false otherwise
     */

    public static boolean isirreducible(int p)
    {
        if (p == 0)
        {
            return false;
        }
        int d = degree(p) >>> 1;
        int u = 2;
        for (int i = 0; i < d; i++)
        {
            u = modmultiply(u, u, p);
            if (gcd(u ^ 2, p) != 1)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * creates irreducible polynomial with degree d
     *
     * @param deg polynomial degree
     * @return irreducible polynomial p
     */
    public static int getirreduciblepolynomial(int deg)
    {
        if (deg < 0)
        {
            system.err.println("the degree is negative");
            return 0;
        }
        if (deg > 31)
        {
            system.err.println("the degree is more then 31");
            return 0;
        }
        if (deg == 0)
        {
            return 1;
        }
        int a = 1 << deg;
        a++;
        int b = 1 << (deg + 1);
        for (int i = a; i < b; i += 2)
        {
            if (isirreducible(i))
            {
                return i;
            }
        }
        return 0;
    }

}
