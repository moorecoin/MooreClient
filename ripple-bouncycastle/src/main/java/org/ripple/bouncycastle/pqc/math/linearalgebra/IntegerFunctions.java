package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.math.biginteger;
import java.security.securerandom;

/**
 * class of number-theory related functions for use with integers represented as
 * <tt>int</tt>'s or <tt>biginteger</tt> objects.
 */
public final class integerfunctions
{

    private static final biginteger zero = biginteger.valueof(0);

    private static final biginteger one = biginteger.valueof(1);

    private static final biginteger two = biginteger.valueof(2);

    private static final biginteger four = biginteger.valueof(4);

    private static final int[] small_primes = {3, 5, 7, 11, 13, 17, 19, 23,
        29, 31, 37, 41};

    private static final long small_prime_product = 3l * 5 * 7 * 11 * 13 * 17
        * 19 * 23 * 29 * 31 * 37 * 41;

    private static securerandom sr = null;

    // the jacobi function uses this lookup table
    private static final int[] jacobitable = {0, 1, 0, -1, 0, -1, 0, 1};

    private integerfunctions()
    {
        // empty
    }

    /**
     * computes the value of the jacobi symbol (a|b). the following properties
     * hold for the jacobi symbol which makes it a very efficient way to
     * evaluate the legendre symbol
     * <p/>
     * (a|b) = 0 if gcd(a,b) > 1<br>
     * (-1|b) = 1 if n = 1 (mod 1)<br>
     * (-1|b) = -1 if n = 3 (mod 4)<br>
     * (a|b) (c|b) = (ac|b)<br>
     * (a|b) (a|c) = (a|cb)<br>
     * (a|b) = (c|b) if a = c (mod b)<br>
     * (2|b) = 1 if n = 1 or 7 (mod 8)<br>
     * (2|b) = 1 if n = 3 or 5 (mod 8)
     * <p/>
     *
     * @param a integer value
     * @param b integer value
     * @return value of the jacobi symbol (a|b)
     */
    public static int jacobi(biginteger a, biginteger b)
    {
        biginteger a, b, v;
        long k = 1;

        k = 1;

        // test trivial cases
        if (b.equals(zero))
        {
            a = a.abs();
            return a.equals(one) ? 1 : 0;
        }

        if (!a.testbit(0) && !b.testbit(0))
        {
            return 0;
        }

        a = a;
        b = b;

        if (b.signum() == -1)
        { // b < 0
            b = b.negate(); // b = -b
            if (a.signum() == -1)
            {
                k = -1;
            }
        }

        v = zero;
        while (!b.testbit(0))
        {
            v = v.add(one); // v = v + 1
            b = b.divide(two); // b = b/2
        }

        if (v.testbit(0))
        {
            k = k * jacobitable[a.intvalue() & 7];
        }

        if (a.signum() < 0)
        { // a < 0
            if (b.testbit(1))
            {
                k = -k; // k = -k
            }
            a = a.negate(); // a = -a
        }

        // main loop
        while (a.signum() != 0)
        {
            v = zero;
            while (!a.testbit(0))
            { // a is even
                v = v.add(one);
                a = a.divide(two);
            }
            if (v.testbit(0))
            {
                k = k * jacobitable[b.intvalue() & 7];
            }

            if (a.compareto(b) < 0)
            { // a < b
                // swap and correct intermediate result
                biginteger x = a;
                a = b;
                b = x;
                if (a.testbit(1) && b.testbit(1))
                {
                    k = -k;
                }
            }
            a = a.subtract(b);
        }

        return b.equals(one) ? (int)k : 0;
    }

    /**
     * computes the square root of a biginteger modulo a prime employing the
     * shanks-tonelli algorithm.
     *
     * @param a value out of which we extract the square root
     * @param p prime modulus that determines the underlying field
     * @return a number <tt>b</tt> such that b<sup>2</sup> = a (mod p) if
     *         <tt>a</tt> is a quadratic residue modulo <tt>p</tt>.
     * @throws noquadraticresidueexception if <tt>a</tt> is a quadratic non-residue modulo <tt>p</tt>
     */
    public static biginteger ressol(biginteger a, biginteger p)
        throws illegalargumentexception
    {

        biginteger v = null;

        if (a.compareto(zero) < 0)
        {
            a = a.add(p);
        }

        if (a.equals(zero))
        {
            return zero;
        }

        if (p.equals(two))
        {
            return a;
        }

        // p = 3 mod 4
        if (p.testbit(0) && p.testbit(1))
        {
            if (jacobi(a, p) == 1)
            { // a quadr. residue mod p
                v = p.add(one); // v = p+1
                v = v.shiftright(2); // v = v/4
                return a.modpow(v, p); // return a^v mod p
                // return --> a^((p+1)/4) mod p
            }
            throw new illegalargumentexception("no quadratic residue: " + a + ", " + p);
        }

        long t = 0;

        // initialization
        // compute k and s, where p = 2^s (2k+1) +1

        biginteger k = p.subtract(one); // k = p-1
        long s = 0;
        while (!k.testbit(0))
        { // while k is even
            s++; // s = s+1
            k = k.shiftright(1); // k = k/2
        }

        k = k.subtract(one); // k = k - 1
        k = k.shiftright(1); // k = k/2

        // initial values
        biginteger r = a.modpow(k, p); // r = a^k mod p

        biginteger n = r.multiply(r).remainder(p); // n = r^2 % p
        n = n.multiply(a).remainder(p); // n = n * a % p
        r = r.multiply(a).remainder(p); // r = r * a %p

        if (n.equals(one))
        {
            return r;
        }

        // non-quadratic residue
        biginteger z = two; // z = 2
        while (jacobi(z, p) == 1)
        {
            // while z quadratic residue
            z = z.add(one); // z = z + 1
        }

        v = k;
        v = v.multiply(two); // v = 2k
        v = v.add(one); // v = 2k + 1
        biginteger c = z.modpow(v, p); // c = z^v mod p

        // iteration
        while (n.compareto(one) == 1)
        { // n > 1
            k = n; // k = n
            t = s; // t = s
            s = 0;

            while (!k.equals(one))
            { // k != 1
                k = k.multiply(k).mod(p); // k = k^2 % p
                s++; // s = s + 1
            }

            t -= s; // t = t - s
            if (t == 0)
            {
                throw new illegalargumentexception("no quadratic residue: " + a + ", " + p);
            }

            v = one;
            for (long i = 0; i < t - 1; i++)
            {
                v = v.shiftleft(1); // v = 1 * 2^(t - 1)
            }
            c = c.modpow(v, p); // c = c^v mod p
            r = r.multiply(c).remainder(p); // r = r * c % p
            c = c.multiply(c).remainder(p); // c = c^2 % p
            n = n.multiply(c).mod(p); // n = n * c % p
        }
        return r;
    }

    /**
     * computes the greatest common divisor of the two specified integers
     *
     * @param u - first integer
     * @param v - second integer
     * @return gcd(a, b)
     */
    public static int gcd(int u, int v)
    {
        return biginteger.valueof(u).gcd(biginteger.valueof(v)).intvalue();
    }

    /**
     * extended euclidian algorithm (computes gcd and representation).
     *
     * @param a the first integer
     * @param b the second integer
     * @return <tt>(g,u,v)</tt>, where <tt>g = gcd(abs(a),abs(b)) = ua + vb</tt>
     */
    public static int[] extgcd(int a, int b)
    {
        biginteger ba = biginteger.valueof(a);
        biginteger bb = biginteger.valueof(b);
        biginteger[] bresult = extgcd(ba, bb);
        int[] result = new int[3];
        result[0] = bresult[0].intvalue();
        result[1] = bresult[1].intvalue();
        result[2] = bresult[2].intvalue();
        return result;
    }

    public static biginteger divideandround(biginteger a, biginteger b)
    {
        if (a.signum() < 0)
        {
            return divideandround(a.negate(), b).negate();
        }
        if (b.signum() < 0)
        {
            return divideandround(a, b.negate()).negate();
        }
        return a.shiftleft(1).add(b).divide(b.shiftleft(1));
    }

    public static biginteger[] divideandround(biginteger[] a, biginteger b)
    {
        biginteger[] out = new biginteger[a.length];
        for (int i = 0; i < a.length; i++)
        {
            out[i] = divideandround(a[i], b);
        }
        return out;
    }

    /**
     * compute the smallest integer that is greater than or equal to the
     * logarithm to the base 2 of the given biginteger.
     *
     * @param a the integer
     * @return ceil[log(a)]
     */
    public static int ceillog(biginteger a)
    {
        int result = 0;
        biginteger p = one;
        while (p.compareto(a) < 0)
        {
            result++;
            p = p.shiftleft(1);
        }
        return result;
    }

    /**
     * compute the smallest integer that is greater than or equal to the
     * logarithm to the base 2 of the given integer.
     *
     * @param a the integer
     * @return ceil[log(a)]
     */
    public static int ceillog(int a)
    {
        int log = 0;
        int i = 1;
        while (i < a)
        {
            i <<= 1;
            log++;
        }
        return log;
    }

    /**
     * compute <tt>ceil(log_256 n)</tt>, the number of bytes needed to encode
     * the integer <tt>n</tt>.
     *
     * @param n the integer
     * @return the number of bytes needed to encode <tt>n</tt>
     */
    public static int ceillog256(int n)
    {
        if (n == 0)
        {
            return 1;
        }
        int m;
        if (n < 0)
        {
            m = -n;
        }
        else
        {
            m = n;
        }

        int d = 0;
        while (m > 0)
        {
            d++;
            m >>>= 8;
        }
        return d;
    }

    /**
     * compute <tt>ceil(log_256 n)</tt>, the number of bytes needed to encode
     * the long integer <tt>n</tt>.
     *
     * @param n the long integer
     * @return the number of bytes needed to encode <tt>n</tt>
     */
    public static int ceillog256(long n)
    {
        if (n == 0)
        {
            return 1;
        }
        long m;
        if (n < 0)
        {
            m = -n;
        }
        else
        {
            m = n;
        }

        int d = 0;
        while (m > 0)
        {
            d++;
            m >>>= 8;
        }
        return d;
    }

    /**
     * compute the integer part of the logarithm to the base 2 of the given
     * integer.
     *
     * @param a the integer
     * @return floor[log(a)]
     */
    public static int floorlog(biginteger a)
    {
        int result = -1;
        biginteger p = one;
        while (p.compareto(a) <= 0)
        {
            result++;
            p = p.shiftleft(1);
        }
        return result;
    }

    /**
     * compute the integer part of the logarithm to the base 2 of the given
     * integer.
     *
     * @param a the integer
     * @return floor[log(a)]
     */
    public static int floorlog(int a)
    {
        int h = 0;
        if (a <= 0)
        {
            return -1;
        }
        int p = a >>> 1;
        while (p > 0)
        {
            h++;
            p >>>= 1;
        }

        return h;
    }

    /**
     * compute the largest <tt>h</tt> with <tt>2^h | a</tt> if <tt>a!=0</tt>.
     *
     * @param a an integer
     * @return the largest <tt>h</tt> with <tt>2^h | a</tt> if <tt>a!=0</tt>,
     *         <tt>0</tt> otherwise
     */
    public static int maxpower(int a)
    {
        int h = 0;
        if (a != 0)
        {
            int p = 1;
            while ((a & p) == 0)
            {
                h++;
                p <<= 1;
            }
        }

        return h;
    }

    /**
     * @param a an integer
     * @return the number of ones in the binary representation of an integer
     *         <tt>a</tt>
     */
    public static int bitcount(int a)
    {
        int h = 0;
        while (a != 0)
        {
            h += a & 1;
            a >>>= 1;
        }

        return h;
    }

    /**
     * determines the order of g modulo p, p prime and 1 < g < p. this algorithm
     * is only efficient for small p (see x9.62-1998, p. 68).
     *
     * @param g an integer with 1 < g < p
     * @param p a prime
     * @return the order k of g (that is k is the smallest integer with
     *         g<sup>k</sup> = 1 mod p
     */
    public static int order(int g, int p)
    {
        int b, j;

        b = g % p; // reduce g mod p first.
        j = 1;

        // check whether g == 0 mod p (avoiding endless loop).
        if (b == 0)
        {
            throw new illegalargumentexception(g + " is not an element of z/("
                + p + "z)^*; it is not meaningful to compute its order.");
        }

        // compute the order of g mod p:
        while (b != 1)
        {
            b *= g;
            b %= p;
            if (b < 0)
            {
                b += p;
            }
            j++;
        }

        return j;
    }

    /**
     * reduces an integer into a given interval
     *
     * @param n     - the integer
     * @param begin - left bound of the interval
     * @param end   - right bound of the interval
     * @return <tt>n</tt> reduced into <tt>[begin,end]</tt>
     */
    public static biginteger reduceinto(biginteger n, biginteger begin,
                                        biginteger end)
    {
        return n.subtract(begin).mod(end.subtract(begin)).add(begin);
    }

    /**
     * compute <tt>a<sup>e</sup></tt>.
     *
     * @param a the base
     * @param e the exponent
     * @return <tt>a<sup>e</sup></tt>
     */
    public static int pow(int a, int e)
    {
        int result = 1;
        while (e > 0)
        {
            if ((e & 1) == 1)
            {
                result *= a;
            }
            a *= a;
            e >>>= 1;
        }
        return result;
    }

    /**
     * compute <tt>a<sup>e</sup></tt>.
     *
     * @param a the base
     * @param e the exponent
     * @return <tt>a<sup>e</sup></tt>
     */
    public static long pow(long a, int e)
    {
        long result = 1;
        while (e > 0)
        {
            if ((e & 1) == 1)
            {
                result *= a;
            }
            a *= a;
            e >>>= 1;
        }
        return result;
    }

    /**
     * compute <tt>a<sup>e</sup> mod n</tt>.
     *
     * @param a the base
     * @param e the exponent
     * @param n the modulus
     * @return <tt>a<sup>e</sup> mod n</tt>
     */
    public static int modpow(int a, int e, int n)
    {
        if (n <= 0 || (n * n) > integer.max_value || e < 0)
        {
            return 0;
        }
        int result = 1;
        a = (a % n + n) % n;
        while (e > 0)
        {
            if ((e & 1) == 1)
            {
                result = (result * a) % n;
            }
            a = (a * a) % n;
            e >>>= 1;
        }
        return result;
    }

    /**
     * extended euclidian algorithm (computes gcd and representation).
     *
     * @param a - the first integer
     * @param b - the second integer
     * @return <tt>(d,u,v)</tt>, where <tt>d = gcd(a,b) = ua + vb</tt>
     */
    public static biginteger[] extgcd(biginteger a, biginteger b)
    {
        biginteger u = one;
        biginteger v = zero;
        biginteger d = a;
        if (b.signum() != 0)
        {
            biginteger v1 = zero;
            biginteger v3 = b;
            while (v3.signum() != 0)
            {
                biginteger[] tmp = d.divideandremainder(v3);
                biginteger q = tmp[0];
                biginteger t3 = tmp[1];
                biginteger t1 = u.subtract(q.multiply(v1));
                u = v1;
                d = v3;
                v1 = t1;
                v3 = t3;
            }
            v = d.subtract(a.multiply(u)).divide(b);
        }
        return new biginteger[]{d, u, v};
    }

    /**
     * computation of the least common multiple of a set of bigintegers.
     *
     * @param numbers - the set of numbers
     * @return the lcm(numbers)
     */
    public static biginteger leastcommonmultiple(biginteger[] numbers)
    {
        int n = numbers.length;
        biginteger result = numbers[0];
        for (int i = 1; i < n; i++)
        {
            biginteger gcd = result.gcd(numbers[i]);
            result = result.multiply(numbers[i]).divide(gcd);
        }
        return result;
    }

    /**
     * returns a long integer whose value is <tt>(a mod m</tt>). this method
     * differs from <tt>%</tt> in that it always returns a <i>non-negative</i>
     * integer.
     *
     * @param a value on which the modulo operation has to be performed.
     * @param m the modulus.
     * @return <tt>a mod m</tt>
     */
    public static long mod(long a, long m)
    {
        long result = a % m;
        if (result < 0)
        {
            result += m;
        }
        return result;
    }

    /**
     * computes the modular inverse of an integer a
     *
     * @param a   - the integer to invert
     * @param mod - the modulus
     * @return <tt>a<sup>-1</sup> mod n</tt>
     */
    public static int modinverse(int a, int mod)
    {
        return biginteger.valueof(a).modinverse(biginteger.valueof(mod))
            .intvalue();
    }

    /**
     * computes the modular inverse of an integer a
     *
     * @param a   - the integer to invert
     * @param mod - the modulus
     * @return <tt>a<sup>-1</sup> mod n</tt>
     */
    public static long modinverse(long a, long mod)
    {
        return biginteger.valueof(a).modinverse(biginteger.valueof(mod))
            .longvalue();
    }

    /**
     * tests whether an integer <tt>a</tt> is power of another integer
     * <tt>p</tt>.
     *
     * @param a - the first integer
     * @param p - the second integer
     * @return n if a = p^n or -1 otherwise
     */
    public static int ispower(int a, int p)
    {
        if (a <= 0)
        {
            return -1;
        }
        int n = 0;
        int d = a;
        while (d > 1)
        {
            if (d % p != 0)
            {
                return -1;
            }
            d /= p;
            n++;
        }
        return n;
    }

    /**
     * find and return the least non-trivial divisor of an integer <tt>a</tt>.
     *
     * @param a - the integer
     * @return divisor p >1 or 1 if a = -1,0,1
     */
    public static int leastdiv(int a)
    {
        if (a < 0)
        {
            a = -a;
        }
        if (a == 0)
        {
            return 1;
        }
        if ((a & 1) == 0)
        {
            return 2;
        }
        int p = 3;
        while (p <= (a / p))
        {
            if ((a % p) == 0)
            {
                return p;
            }
            p += 2;
        }

        return a;
    }

    /**
     * miller-rabin-test, determines wether the given integer is probably prime
     * or composite. this method returns <tt>true</tt> if the given integer is
     * prime with probability <tt>1 - 2<sup>-20</sup></tt>.
     *
     * @param n the integer to test for primality
     * @return <tt>true</tt> if the given integer is prime with probability
     *         2<sup>-100</sup>, <tt>false</tt> otherwise
     */
    public static boolean isprime(int n)
    {
        if (n < 2)
        {
            return false;
        }
        if (n == 2)
        {
            return true;
        }
        if ((n & 1) == 0)
        {
            return false;
        }
        if (n < 42)
        {
            for (int i = 0; i < small_primes.length; i++)
            {
                if (n == small_primes[i])
                {
                    return true;
                }
            }
        }

        if ((n % 3 == 0) || (n % 5 == 0) || (n % 7 == 0) || (n % 11 == 0)
            || (n % 13 == 0) || (n % 17 == 0) || (n % 19 == 0)
            || (n % 23 == 0) || (n % 29 == 0) || (n % 31 == 0)
            || (n % 37 == 0) || (n % 41 == 0))
        {
            return false;
        }

        return biginteger.valueof(n).isprobableprime(20);
    }

    /**
     * short trial-division test to find out whether a number is not prime. this
     * test is usually used before a miller-rabin primality test.
     *
     * @param candidate the number to test
     * @return <tt>true</tt> if the number has no factor of the tested primes,
     *         <tt>false</tt> if the number is definitely composite
     */
    public static boolean passessmallprimetest(biginteger candidate)
    {
        final int[] smallprime = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
            41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
            107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
            173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
            239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
            311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
            383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
            457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523,
            541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
            613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677,
            683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761,
            769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853,
            857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
            941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
            1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087,
            1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
            1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229,
            1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297,
            1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381,
            1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453,
            1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499};

        for (int i = 0; i < smallprime.length; i++)
        {
            if (candidate.mod(biginteger.valueof(smallprime[i])).equals(
                zero))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * returns the largest prime smaller than the given integer
     *
     * @param n - upper bound
     * @return the largest prime smaller than <tt>n</tt>, or <tt>1</tt> if
     *         <tt>n &lt;= 2</tt>
     */
    public static int nextsmallerprime(int n)
    {
        if (n <= 2)
        {
            return 1;
        }

        if (n == 3)
        {
            return 2;
        }

        if ((n & 1) == 0)
        {
            n--;
        }
        else
        {
            n -= 2;
        }

        while (n > 3 & !isprime(n))
        {
            n -= 2;
        }
        return n;
    }

    /**
     * compute the next probable prime greater than <tt>n</tt> with the
     * specified certainty.
     *
     * @param n         a integer number
     * @param certainty the certainty that the generated number is prime
     * @return the next prime greater than <tt>n</tt>
     */
    public static biginteger nextprobableprime(biginteger n, int certainty)
    {

        if (n.signum() < 0 || n.signum() == 0 || n.equals(one))
        {
            return two;
        }

        biginteger result = n.add(one);

        // ensure an odd number
        if (!result.testbit(0))
        {
            result = result.add(one);
        }

        while (true)
        {
            // do cheap "pre-test" if applicable
            if (result.bitlength() > 6)
            {
                long r = result.remainder(
                    biginteger.valueof(small_prime_product)).longvalue();
                if ((r % 3 == 0) || (r % 5 == 0) || (r % 7 == 0)
                    || (r % 11 == 0) || (r % 13 == 0) || (r % 17 == 0)
                    || (r % 19 == 0) || (r % 23 == 0) || (r % 29 == 0)
                    || (r % 31 == 0) || (r % 37 == 0) || (r % 41 == 0))
                {
                    result = result.add(two);
                    continue; // candidate is composite; try another
                }
            }

            // all candidates of bitlength 2 and 3 are prime by this point
            if (result.bitlength() < 4)
            {
                return result;
            }

            // the expensive test
            if (result.isprobableprime(certainty))
            {
                return result;
            }

            result = result.add(two);
        }
    }

    /**
     * compute the next probable prime greater than <tt>n</tt> with the default
     * certainty (20).
     *
     * @param n a integer number
     * @return the next prime greater than <tt>n</tt>
     */
    public static biginteger nextprobableprime(biginteger n)
    {
        return nextprobableprime(n, 20);
    }

    /**
     * computes the next prime greater than n.
     *
     * @param n a integer number
     * @return the next prime greater than n
     */
    public static biginteger nextprime(long n)
    {
        long i;
        boolean found = false;
        long result = 0;

        if (n <= 1)
        {
            return biginteger.valueof(2);
        }
        if (n == 2)
        {
            return biginteger.valueof(3);
        }

        for (i = n + 1 + (n & 1); (i <= n << 1) && !found; i += 2)
        {
            for (long j = 3; (j <= i >> 1) && !found; j += 2)
            {
                if (i % j == 0)
                {
                    found = true;
                }
            }
            if (found)
            {
                found = false;
            }
            else
            {
                result = i;
                found = true;
            }
        }
        return biginteger.valueof(result);
    }

    /**
     * computes the binomial coefficient (n|t) ("n over t"). formula:<br/>
     * <ul>
     * <li>if n !=0 and t != 0 then (n|t) = mult(i=1, t): (n-(i-1))/i</li>
     * <li>if t = 0 then (n|t) = 1</li>
     * <li>if n = 0 and t > 0 then (n|t) = 0</li>
     * </ul>
     *
     * @param n - the "upper" integer
     * @param t - the "lower" integer
     * @return the binomialcoefficient "n over t" as biginteger
     */
    public static biginteger binomial(int n, int t)
    {

        biginteger result = one;

        if (n == 0)
        {
            if (t == 0)
            {
                return result;
            }
            return zero;
        }

        // the property (n|t) = (n|n-t) be used to reduce numbers of operations
        if (t > (n >>> 1))
        {
            t = n - t;
        }

        for (int i = 1; i <= t; i++)
        {
            result = (result.multiply(biginteger.valueof(n - (i - 1))))
                .divide(biginteger.valueof(i));
        }

        return result;
    }

    public static biginteger randomize(biginteger upperbound)
    {
        if (sr == null)
        {
            sr = new securerandom();
        }
        return randomize(upperbound, sr);
    }

    public static biginteger randomize(biginteger upperbound,
                                       securerandom prng)
    {
        int blen = upperbound.bitlength();
        biginteger randomnum = biginteger.valueof(0);

        if (prng == null)
        {
            prng = sr != null ? sr : new securerandom();
        }

        for (int i = 0; i < 20; i++)
        {
            randomnum = new biginteger(blen, prng);
            if (randomnum.compareto(upperbound) < 0)
            {
                return randomnum;
            }
        }
        return randomnum.mod(upperbound);
    }

    /**
     * extract the truncated square root of a biginteger.
     *
     * @param a - value out of which we extract the square root
     * @return the truncated square root of <tt>a</tt>
     */
    public static biginteger squareroot(biginteger a)
    {
        int bl;
        biginteger result, remainder, b;

        if (a.compareto(zero) < 0)
        {
            throw new arithmeticexception(
                "cannot extract root of negative number" + a + ".");
        }

        bl = a.bitlength();
        result = zero;
        remainder = zero;

        // if the bit length is odd then extra step
        if ((bl & 1) != 0)
        {
            result = result.add(one);
            bl--;
        }

        while (bl > 0)
        {
            remainder = remainder.multiply(four);
            remainder = remainder.add(biginteger.valueof((a.testbit(--bl) ? 2
                : 0)
                + (a.testbit(--bl) ? 1 : 0)));
            b = result.multiply(four).add(one);
            result = result.multiply(two);
            if (remainder.compareto(b) != -1)
            {
                result = result.add(one);
                remainder = remainder.subtract(b);
            }
        }

        return result;
    }

    /**
     * takes an approximation of the root from an integer base, using newton's
     * algorithm
     *
     * @param base the base to take the root from
     * @param root the root, for example 2 for a square root
     */
    public static float introot(int base, int root)
    {
        float gnew = base / root;
        float gold = 0;
        int counter = 0;
        while (math.abs(gold - gnew) > 0.0001)
        {
            float gpow = floatpow(gnew, root);
            while (float.isinfinite(gpow))
            {
                gnew = (gnew + gold) / 2;
                gpow = floatpow(gnew, root);
            }
            counter += 1;
            gold = gnew;
            gnew = gold - (gpow - base) / (root * floatpow(gold, root - 1));
        }
        return gnew;
    }

    /**
     * calculation of a logarithmus of a float param
     *
     * @param param
     * @return
     */
    public static float floatlog(float param)
    {
        double arg = (param - 1) / (param + 1);
        double arg2 = arg;
        int counter = 1;
        float result = (float)arg;

        while (arg2 > 0.001)
        {
            counter += 2;
            arg2 *= arg * arg;
            result += (1. / counter) * arg2;
        }
        return 2 * result;
    }

    /**
     * int power of a base float, only use for small ints
     *
     * @param f
     * @param i
     * @return
     */
    public static float floatpow(float f, int i)
    {
        float g = 1;
        for (; i > 0; i--)
        {
            g *= f;
        }
        return g;
    }

    /**
     * calculate the logarithm to the base 2.
     *
     * @param x any double value
     * @return log_2(x)
     * @deprecated use mathfunctions.log(double) instead
     */
    public static double log(double x)
    {
        if (x > 0 && x < 1)
        {
            double d = 1 / x;
            double result = -log(d);
            return result;
        }

        int tmp = 0;
        double tmp2 = 1;
        double d = x;

        while (d > 2)
        {
            d = d / 2;
            tmp += 1;
            tmp2 *= 2;
        }
        double rem = x / tmp2;
        rem = logbkm(rem);
        return tmp + rem;
    }

    /**
     * calculate the logarithm to the base 2.
     *
     * @param x any long value >=1
     * @return log_2(x)
     * @deprecated use mathfunctions.log(long) instead
     */
    public static double log(long x)
    {
        int tmp = floorlog(biginteger.valueof(x));
        long tmp2 = 1 << tmp;
        double rem = (double)x / (double)tmp2;
        rem = logbkm(rem);
        return tmp + rem;
    }

    /**
     * bkm algorithm to calculate logarithms to the base 2.
     *
     * @param arg a double value with 1<= arg<= 4.768462058
     * @return log_2(arg)
     * @deprecated use mathfunctions.logbkm(double) instead
     */
    private static double logbkm(double arg)
    {
        double ae[] = // a_e[k] = log_2 (1 + 0.5^k)
            {
                1.0000000000000000000000000000000000000000000000000000000000000000000000000000,
                0.5849625007211561814537389439478165087598144076924810604557526545410982276485,
                0.3219280948873623478703194294893901758648313930245806120547563958159347765589,
                0.1699250014423123629074778878956330175196288153849621209115053090821964552970,
                0.0874628412503394082540660108104043540112672823448206881266090643866965081686,
                0.0443941193584534376531019906736094674630459333742491317685543002674288465967,
                0.0223678130284545082671320837460849094932677948156179815932199216587899627785,
                0.0112272554232541203378805844158839407281095943600297940811823651462712311786,
                0.0056245491938781069198591026740666017211096815383520359072957784732489771013,
                0.0028150156070540381547362547502839489729507927389771959487826944878598909400,
                0.0014081943928083889066101665016890524233311715793462235597709051792834906001,
                0.0007042690112466432585379340422201964456668872087249334581924550139514213168,
                0.0003521774803010272377989609925281744988670304302127133979341729842842377649,
                0.0001760994864425060348637509459678580940163670081839283659942864068257522373,
                0.0000880524301221769086378699983597183301490534085738474534831071719854721939,
                0.0000440268868273167176441087067175806394819146645511899503059774914593663365,
                0.0000220136113603404964890728830697555571275493801909791504158295359319433723,
                0.0000110068476674814423006223021573490183469930819844945565597452748333526464,
                0.0000055034343306486037230640321058826431606183125807276574241540303833251704,
                0.0000027517197895612831123023958331509538486493412831626219340570294203116559,
                0.0000013758605508411382010566802834037147561973553922354232704569052932922954,
                0.0000006879304394358496786728937442939160483304056131990916985043387874690617,
                0.0000003439652607217645360118314743718005315334062644619363447395987584138324,
                0.0000001719826406118446361936972479533123619972434705828085978955697643547921,
                0.0000000859913228686632156462565208266682841603921494181830811515318381744650,
                0.0000000429956620750168703982940244684787907148132725669106053076409624949917,
                0.0000000214978311976797556164155504126645192380395989504741781512309853438587,
                0.0000000107489156388827085092095702361647949603617203979413516082280717515504,
                0.0000000053744578294520620044408178949217773318785601260677517784797554422804,
                0.0000000026872289172287079490026152352638891824761667284401180026908031182361,
                0.0000000013436144592400232123622589569799954658536700992739887706412976115422,
                0.0000000006718072297764289157920422846078078155859484240808550018085324187007,
                0.0000000003359036149273187853169587152657145221968468364663464125722491530858,
                0.0000000001679518074734354745159899223037458278711244127245990591908996412262,
                0.0000000000839759037391617577226571237484864917411614198675604731728132152582,
                0.0000000000419879518701918839775296677020135040214077417929807824842667285938,
                0.0000000000209939759352486932678195559552767641474249812845414125580747434389,
                0.0000000000104969879676625344536740142096218372850561859495065136990936290929,
                0.0000000000052484939838408141817781356260462777942148580518406975851213868092,
                0.0000000000026242469919227938296243586262369156865545638305682553644113887909,
                0.0000000000013121234959619935994960031017850191710121890821178731821983105443,
                0.0000000000006560617479811459709189576337295395590603644549624717910616347038,
                0.0000000000003280308739906102782522178545328259781415615142931952662153623493,
                0.0000000000001640154369953144623242936888032768768777422997704541618141646683,
                0.0000000000000820077184976595619616930350508356401599552034612281802599177300,
                0.0000000000000410038592488303636807330652208397742314215159774270270147020117,
                0.0000000000000205019296244153275153381695384157073687186580546938331088730952,
                0.0000000000000102509648122077001764119940017243502120046885379813510430378661,
                0.0000000000000051254824061038591928917243090559919209628584150482483994782302,
                0.0000000000000025627412030519318726172939815845367496027046030028595094737777,
                0.0000000000000012813706015259665053515049475574143952543145124550608158430592,
                0.0000000000000006406853007629833949364669629701200556369782295210193569318434,
                0.0000000000000003203426503814917330334121037829290364330169106716787999052925,
                0.0000000000000001601713251907458754080007074659337446341494733882570243497196,
                0.0000000000000000800856625953729399268240176265844257044861248416330071223615,
                0.0000000000000000400428312976864705191179247866966320469710511619971334577509,
                0.0000000000000000200214156488432353984854413866994246781519154793320684126179,
                0.0000000000000000100107078244216177339743404416874899847406043033792202127070,
                0.0000000000000000050053539122108088756700751579281894640362199287591340285355,
                0.0000000000000000025026769561054044400057638132352058574658089256646014899499,
                0.0000000000000000012513384780527022205455634651853807110362316427807660551208,
                0.0000000000000000006256692390263511104084521222346348012116229213309001913762,
                0.0000000000000000003128346195131755552381436585278035120438976487697544916191,
                0.0000000000000000001564173097565877776275512286165232838833090480508502328437,
                0.0000000000000000000782086548782938888158954641464170239072244145219054734086,
                0.0000000000000000000391043274391469444084776945327473574450334092075712154016,
                0.0000000000000000000195521637195734722043713378812583900953755962557525252782,
                0.0000000000000000000097760818597867361022187915943503728909029699365320287407,
                0.0000000000000000000048880409298933680511176764606054809062553340323879609794,
                0.0000000000000000000024440204649466840255609083961603140683286362962192177597,
                0.0000000000000000000012220102324733420127809717395445504379645613448652614939,
                0.0000000000000000000006110051162366710063906152551383735699323415812152114058,
                0.0000000000000000000003055025581183355031953399739107113727036860315024588989,
                0.0000000000000000000001527512790591677515976780735407368332862218276873443537,
                0.0000000000000000000000763756395295838757988410584167137033767056170417508383,
                0.0000000000000000000000381878197647919378994210346199431733717514843471513618,
                0.0000000000000000000000190939098823959689497106436628681671067254111334889005,
                0.0000000000000000000000095469549411979844748553534196582286585751228071408728,
                0.0000000000000000000000047734774705989922374276846068851506055906657137209047,
                0.0000000000000000000000023867387352994961187138442777065843718711089344045782,
                0.0000000000000000000000011933693676497480593569226324192944532044984865894525,
                0.0000000000000000000000005966846838248740296784614396011477934194852481410926,
                0.0000000000000000000000002983423419124370148392307506484490384140516252814304,
                0.0000000000000000000000001491711709562185074196153830361933046331030629430117,
                0.0000000000000000000000000745855854781092537098076934460888486730708440475045,
                0.0000000000000000000000000372927927390546268549038472050424734256652501673274,
                0.0000000000000000000000000186463963695273134274519237230207489851150821191330,
                0.0000000000000000000000000093231981847636567137259618916352525606281553180093,
                0.0000000000000000000000000046615990923818283568629809533488457973317312233323,
                0.0000000000000000000000000023307995461909141784314904785572277779202790023236,
                0.0000000000000000000000000011653997730954570892157452397493151087737428485431,
                0.0000000000000000000000000005826998865477285446078726199923328593402722606924,
                0.0000000000000000000000000002913499432738642723039363100255852559084863397344,
                0.0000000000000000000000000001456749716369321361519681550201473345138307215067,
                0.0000000000000000000000000000728374858184660680759840775119123438968122488047,
                0.0000000000000000000000000000364187429092330340379920387564158411083803465567,
                0.0000000000000000000000000000182093714546165170189960193783228378441837282509,
                0.0000000000000000000000000000091046857273082585094980096891901482445902524441,
                0.0000000000000000000000000000045523428636541292547490048446022564529197237262,
                0.0000000000000000000000000000022761714318270646273745024223029238091160103901};
        int n = 53;
        double x = 1;
        double y = 0;
        double z;
        double s = 1;
        int k;

        for (k = 0; k < n; k++)
        {
            z = x + x * s;
            if (z <= arg)
            {
                x = z;
                y += ae[k];
            }
            s *= 0.5;
        }
        return y;
    }

    public static boolean isincreasing(int[] a)
    {
        for (int i = 1; i < a.length; i++)
        {
            if (a[i - 1] >= a[i])
            {
                system.out.println("a[" + (i - 1) + "] = " + a[i - 1] + " >= "
                    + a[i] + " = a[" + i + "]");
                return false;
            }
        }
        return true;
    }

    public static byte[] integertooctets(biginteger val)
    {
        byte[] valbytes = val.abs().tobytearray();

        // check whether the array includes a sign bit
        if ((val.bitlength() & 7) != 0)
        {
            return valbytes;
        }
        // get rid of the sign bit (first byte)
        byte[] tmp = new byte[val.bitlength() >> 3];
        system.arraycopy(valbytes, 1, tmp, 0, tmp.length);
        return tmp;
    }

    public static biginteger octetstointeger(byte[] data, int offset,
                                             int length)
    {
        byte[] val = new byte[length + 1];

        val[0] = 0;
        system.arraycopy(data, offset, val, 1, length);
        return new biginteger(val);
    }

    public static biginteger octetstointeger(byte[] data)
    {
        return octetstointeger(data, 0, data.length);
    }

    public static void main(string[] args)
    {
        system.out.println("test");
        // system.out.println(introot(37, 5));
        // system.out.println(floatpow((float)2.5, 4));
        system.out.println(floatlog(10));
        system.out.println("test2");
    }
}
