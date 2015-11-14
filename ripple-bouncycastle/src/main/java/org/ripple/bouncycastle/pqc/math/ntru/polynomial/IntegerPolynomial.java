package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import java.io.ioexception;
import java.io.inputstream;
import java.math.biginteger;
import java.util.arraylist;
import java.util.iterator;
import java.util.linkedlist;
import java.util.list;
import java.util.concurrent.callable;
import java.util.concurrent.executorservice;
import java.util.concurrent.executors;
import java.util.concurrent.future;
import java.util.concurrent.linkedblockingqueue;

import org.ripple.bouncycastle.pqc.math.ntru.euclid.biginteuclidean;
import org.ripple.bouncycastle.pqc.math.ntru.util.arrayencoder;
import org.ripple.bouncycastle.pqc.math.ntru.util.util;
import org.ripple.bouncycastle.util.arrays;

/**
 * a polynomial with <code>int</code> coefficients.<br/>
 * some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class integerpolynomial
    implements polynomial
{
    private static final int num_equal_resultants = 3;
    /**
     * prime numbers &gt; 4500 for resultant computation. starting them below ~4400 causes incorrect results occasionally.
     * fortunately, 4500 is about the optimum number for performance.<br/>
     * this array contains enough prime numbers so primes never have to be computed on-line for any standard {@link org.ripple.bouncycastle.pqc.crypto.ntru.ntrusigningparameters}.
     */
    private static final int[] primes = new int[]{
        4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,
        4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
        4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
        4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
        4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,
        4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,
        5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
        5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,
        5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
        5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
        5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
        5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521,
        5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
        5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,
        5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
        5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
        5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939,
        5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,
        6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
        6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,
        6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,
        6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
        6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
        6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,
        6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,
        6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,
        6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
        6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
        6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997,
        7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
        7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
        7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297,
        7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,
        7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
        7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
        7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643,
        7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,
        7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,
        7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
        7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017,
        8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111,
        8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219,
        8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291,
        8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387,
        8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501,
        8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597,
        8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677,
        8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741,
        8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831,
        8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929,
        8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011,
        9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109,
        9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199,
        9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283,
        9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377,
        9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439,
        9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533,
        9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631,
        9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733,
        9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811,
        9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887,
        9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973};
    private static final list bigint_primes;

    static
    {
        bigint_primes = new arraylist();
        for (int i = 0; i != primes.length; i++)
        {
            bigint_primes.add(biginteger.valueof(primes[i]));
        }
    }

    public int[] coeffs;

    /**
     * constructs a new polynomial with <code>n</code> coefficients initialized to 0.
     *
     * @param n the number of coefficients
     */
    public integerpolynomial(int n)
    {
        coeffs = new int[n];
    }

    /**
     * constructs a new polynomial with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    public integerpolynomial(int[] coeffs)
    {
        this.coeffs = coeffs;
    }

    /**
     * constructs a <code>integerpolynomial</code> from a <code>bigintpolynomial</code>. the two polynomials are independent of each other.
     *
     * @param p the original polynomial
     */
    public integerpolynomial(bigintpolynomial p)
    {
        coeffs = new int[p.coeffs.length];
        for (int i = 0; i < p.coeffs.length; i++)
        {
            coeffs[i] = p.coeffs[i].intvalue();
        }
    }

    /**
     * decodes a byte array to a polynomial with <code>n</code> ternary coefficients<br/>
     * ignores any excess bytes.
     *
     * @param data an encoded ternary polynomial
     * @param n    number of coefficients
     * @return the decoded polynomial
     */
    public static integerpolynomial frombinary3sves(byte[] data, int n)
    {
        return new integerpolynomial(arrayencoder.decodemod3sves(data, n));
    }

    /**
     * converts a byte array produced by {@link #tobinary3tight()} to a polynomial.
     *
     * @param b a byte array
     * @param n number of coefficients
     * @return the decoded polynomial
     */
    public static integerpolynomial frombinary3tight(byte[] b, int n)
    {
        return new integerpolynomial(arrayencoder.decodemod3tight(b, n));
    }

    /**
     * reads data produced by {@link #tobinary3tight()} from an input stream and converts it to a polynomial.
     *
     * @param is an input stream
     * @param n  number of coefficients
     * @return the decoded polynomial
     */
    public static integerpolynomial frombinary3tight(inputstream is, int n)
        throws ioexception
    {
        return new integerpolynomial(arrayencoder.decodemod3tight(is, n));
    }

    /**
     * returns a polynomial with n coefficients between <code>0</code> and <code>q-1</code>.<br/>
     * <code>q</code> must be a power of 2.<br/>
     * ignores any excess bytes.
     *
     * @param data an encoded ternary polynomial
     * @param n    number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    public static integerpolynomial frombinary(byte[] data, int n, int q)
    {
        return new integerpolynomial(arrayencoder.decodemodq(data, n, q));
    }

    /**
     * returns a polynomial with n coefficients between <code>0</code> and <code>q-1</code>.<br/>
     * <code>q</code> must be a power of 2.<br/>
     * ignores any excess bytes.
     *
     * @param is an encoded ternary polynomial
     * @param n  number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    public static integerpolynomial frombinary(inputstream is, int n, int q)
        throws ioexception
    {
        return new integerpolynomial(arrayencoder.decodemodq(is, n, q));
    }

    /**
     * encodes a polynomial with ternary coefficients to binary.
     * <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer </code>i<code>,
     * so this method is only safe to use with polynomials produced by <code>frombinary3sves()</code>.
     *
     * @return the encoded polynomial
     */
    public byte[] tobinary3sves()
    {
        return arrayencoder.encodemod3sves(coeffs);
    }

    /**
     * converts a polynomial with ternary coefficients to binary.
     *
     * @return the encoded polynomial
     */
    public byte[] tobinary3tight()
    {
        biginteger sum = constants.bigint_zero;
        for (int i = coeffs.length - 1; i >= 0; i--)
        {
            sum = sum.multiply(biginteger.valueof(3));
            sum = sum.add(biginteger.valueof(coeffs[i] + 1));
        }

        int size = (biginteger.valueof(3).pow(coeffs.length).bitlength() + 7) / 8;
        byte[] arr = sum.tobytearray();

        if (arr.length < size)
        {
            // pad with leading zeros so arr.length==size
            byte[] arr2 = new byte[size];
            system.arraycopy(arr, 0, arr2, size - arr.length, arr.length);
            return arr2;
        }

        if (arr.length > size)
        // drop sign bit
        {
            arr = arrays.copyofrange(arr, 1, arr.length);
        }
        return arr;
    }

    /**
     * encodes a polynomial whose coefficients are between 0 and q, to binary. q must be a power of 2.
     *
     * @param q
     * @return the encoded polynomial
     */
    public byte[] tobinary(int q)
    {
        return arrayencoder.encodemodq(coeffs, q);
    }

    /**
     * multiplies the polynomial with another, taking the values mod modulus and the indices mod n
     */
    public integerpolynomial mult(integerpolynomial poly2, int modulus)
    {
        integerpolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    /**
     * multiplies the polynomial with another, taking the indices mod n
     */
    public integerpolynomial mult(integerpolynomial poly2)
    {
        int n = coeffs.length;
        if (poly2.coeffs.length != n)
        {
            throw new illegalargumentexception("number of coefficients must be the same");
        }

        integerpolynomial c = multrecursive(poly2);

        if (c.coeffs.length > n)
        {
            for (int k = n; k < c.coeffs.length; k++)
            {
                c.coeffs[k - n] += c.coeffs[k];
            }
            c.coeffs = arrays.copyof(c.coeffs, n);
        }
        return c;
    }

    public bigintpolynomial mult(bigintpolynomial poly2)
    {
        return new bigintpolynomial(this).mult(poly2);
    }

    /**
     * karazuba multiplication
     */
    private integerpolynomial multrecursive(integerpolynomial poly2)
    {
        int[] a = coeffs;
        int[] b = poly2.coeffs;

        int n = poly2.coeffs.length;
        if (n <= 32)
        {
            int cn = 2 * n - 1;
            integerpolynomial c = new integerpolynomial(new int[cn]);
            for (int k = 0; k < cn; k++)
            {
                for (int i = math.max(0, k - n + 1); i <= math.min(k, n - 1); i++)
                {
                    c.coeffs[k] += b[i] * a[k - i];
                }
            }
            return c;
        }
        else
        {
            int n1 = n / 2;

            integerpolynomial a1 = new integerpolynomial(arrays.copyof(a, n1));
            integerpolynomial a2 = new integerpolynomial(arrays.copyofrange(a, n1, n));
            integerpolynomial b1 = new integerpolynomial(arrays.copyof(b, n1));
            integerpolynomial b2 = new integerpolynomial(arrays.copyofrange(b, n1, n));

            integerpolynomial a = (integerpolynomial)a1.clone();
            a.add(a2);
            integerpolynomial b = (integerpolynomial)b1.clone();
            b.add(b2);

            integerpolynomial c1 = a1.multrecursive(b1);
            integerpolynomial c2 = a2.multrecursive(b2);
            integerpolynomial c3 = a.multrecursive(b);
            c3.sub(c1);
            c3.sub(c2);

            integerpolynomial c = new integerpolynomial(2 * n - 1);
            for (int i = 0; i < c1.coeffs.length; i++)
            {
                c.coeffs[i] = c1.coeffs[i];
            }
            for (int i = 0; i < c3.coeffs.length; i++)
            {
                c.coeffs[n1 + i] += c3.coeffs[i];
            }
            for (int i = 0; i < c2.coeffs.length; i++)
            {
                c.coeffs[2 * n1 + i] += c2.coeffs[i];
            }
            return c;
        }
    }

    /**
     * computes the inverse mod <code>q; q</code> must be a power of 2.<br/>
     * returns <code>null</code> if the polynomial is not invertible.
     *
     * @param q the modulus
     * @return a new polynomial
     */
    public integerpolynomial invertfq(int q)
    {
        int n = coeffs.length;
        int k = 0;
        integerpolynomial b = new integerpolynomial(n + 1);
        b.coeffs[0] = 1;
        integerpolynomial c = new integerpolynomial(n + 1);
        integerpolynomial f = new integerpolynomial(n + 1);
        f.coeffs = arrays.copyof(coeffs, n + 1);
        f.modpositive(2);
        // set g(x) = x^n 鈭?1
        integerpolynomial g = new integerpolynomial(n + 1);
        g.coeffs[0] = 1;
        g.coeffs[n] = 1;
        while (true)
        {
            while (f.coeffs[0] == 0)
            {
                for (int i = 1; i <= n; i++)
                {
                    f.coeffs[i - 1] = f.coeffs[i];   // f(x) = f(x) / x
                    c.coeffs[n + 1 - i] = c.coeffs[n - i];   // c(x) = c(x) * x
                }
                f.coeffs[n] = 0;
                c.coeffs[0] = 0;
                k++;
                if (f.equalszero())
                {
                    return null;   // not invertible
                }
            }
            if (f.equalsone())
            {
                break;
            }
            if (f.degree() < g.degree())
            {
                // exchange f and g
                integerpolynomial temp = f;
                f = g;
                g = temp;
                // exchange b and c
                temp = b;
                b = c;
                c = temp;
            }
            f.add(g, 2);
            b.add(c, 2);
        }

        if (b.coeffs[n] != 0)
        {
            return null;
        }
        // fq(x) = x^(n-k) * b(x)
        integerpolynomial fq = new integerpolynomial(n);
        int j = 0;
        k %= n;
        for (int i = n - 1; i >= 0; i--)
        {
            j = i - k;
            if (j < 0)
            {
                j += n;
            }
            fq.coeffs[j] = b.coeffs[i];
        }

        return mod2tomodq(fq, q);
    }

    /**
     * computes the inverse mod q from the inverse mod 2
     *
     * @param fq
     * @param q
     * @return the inverse of this polynomial mod q
     */
    private integerpolynomial mod2tomodq(integerpolynomial fq, int q)
    {
        if (util.is64bitjvm() && q == 2048)
        {
            longpolynomial2 thislong = new longpolynomial2(this);
            longpolynomial2 fqlong = new longpolynomial2(fq);
            int v = 2;
            while (v < q)
            {
                v *= 2;
                longpolynomial2 temp = (longpolynomial2)fqlong.clone();
                temp.mult2and(v - 1);
                fqlong = thislong.mult(fqlong).mult(fqlong);
                temp.suband(fqlong, v - 1);
                fqlong = temp;
            }
            return fqlong.tointegerpolynomial();
        }
        else
        {
            int v = 2;
            while (v < q)
            {
                v *= 2;
                integerpolynomial temp = new integerpolynomial(arrays.copyof(fq.coeffs, fq.coeffs.length));
                temp.mult2(v);
                fq = mult(fq, v).mult(fq, v);
                temp.sub(fq, v);
                fq = temp;
            }
            return fq;
        }
    }

    /**
     * computes the inverse mod 3.
     * returns <code>null</code> if the polynomial is not invertible.
     *
     * @return a new polynomial
     */
    public integerpolynomial invertf3()
    {
        int n = coeffs.length;
        int k = 0;
        integerpolynomial b = new integerpolynomial(n + 1);
        b.coeffs[0] = 1;
        integerpolynomial c = new integerpolynomial(n + 1);
        integerpolynomial f = new integerpolynomial(n + 1);
        f.coeffs = arrays.copyof(coeffs, n + 1);
        f.modpositive(3);
        // set g(x) = x^n 鈭?1
        integerpolynomial g = new integerpolynomial(n + 1);
        g.coeffs[0] = -1;
        g.coeffs[n] = 1;
        while (true)
        {
            while (f.coeffs[0] == 0)
            {
                for (int i = 1; i <= n; i++)
                {
                    f.coeffs[i - 1] = f.coeffs[i];   // f(x) = f(x) / x
                    c.coeffs[n + 1 - i] = c.coeffs[n - i];   // c(x) = c(x) * x
                }
                f.coeffs[n] = 0;
                c.coeffs[0] = 0;
                k++;
                if (f.equalszero())
                {
                    return null;   // not invertible
                }
            }
            if (f.equalsabsone())
            {
                break;
            }
            if (f.degree() < g.degree())
            {
                // exchange f and g
                integerpolynomial temp = f;
                f = g;
                g = temp;
                // exchange b and c
                temp = b;
                b = c;
                c = temp;
            }
            if (f.coeffs[0] == g.coeffs[0])
            {
                f.sub(g, 3);
                b.sub(c, 3);
            }
            else
            {
                f.add(g, 3);
                b.add(c, 3);
            }
        }

        if (b.coeffs[n] != 0)
        {
            return null;
        }
        // fp(x) = [+-] x^(n-k) * b(x)
        integerpolynomial fp = new integerpolynomial(n);
        int j = 0;
        k %= n;
        for (int i = n - 1; i >= 0; i--)
        {
            j = i - k;
            if (j < 0)
            {
                j += n;
            }
            fp.coeffs[j] = f.coeffs[0] * b.coeffs[i];
        }

        fp.ensurepositive(3);
        return fp;
    }

    /**
     * resultant of this polynomial with <code>x^n-1</code> using a probabilistic algorithm.
     * <p/>
     * unlike eess, this implementation does not compute all resultants modulo primes
     * such that their product exceeds the maximum possible resultant, but rather stops
     * when <code>num_equal_resultants</code> consecutive modular resultants are equal.<br/>
     * this means the return value may be incorrect. experiments show this happens in
     * about 1 out of 100 cases when <code>n=439</code> and <code>num_equal_resultants=2</code>,
     * so the likelyhood of leaving the loop too early is <code>(1/100)^(num_equal_resultants-1)</code>.
     * <p/>
     * because of the above, callers must verify the output and try a different polynomial if necessary.
     *
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>.
     */
    public resultant resultant()
    {
        int n = coeffs.length;

        // compute resultants modulo prime numbers. continue until num_equal_resultants consecutive modular resultants are equal.
        linkedlist<modularresultant> modresultants = new linkedlist<modularresultant>();
        biginteger prime = null;
        biginteger pprod = constants.bigint_one;
        biginteger res = constants.bigint_one;
        int numequal = 1;   // number of consecutive modular resultants equal to each other
        iterator<biginteger> primes = bigint_primes.iterator();
        while (true)
        {
            prime = primes.hasnext() ? primes.next() : prime.nextprobableprime();
            modularresultant crr = resultant(prime.intvalue());
            modresultants.add(crr);

            biginteger temp = pprod.multiply(prime);
            biginteuclidean er = biginteuclidean.calculate(prime, pprod);
            biginteger resprev = res;
            res = res.multiply(er.x.multiply(prime));
            biginteger res2 = crr.res.multiply(er.y.multiply(pprod));
            res = res.add(res2).mod(temp);
            pprod = temp;

            biginteger pprod2 = pprod.divide(biginteger.valueof(2));
            biginteger pprod2n = pprod2.negate();
            if (res.compareto(pprod2) > 0)
            {
                res = res.subtract(pprod);
            }
            else if (res.compareto(pprod2n) < 0)
            {
                res = res.add(pprod);
            }

            if (res.equals(resprev))
            {
                numequal++;
                if (numequal >= num_equal_resultants)
                {
                    break;
                }
            }
            else
            {
                numequal = 1;
            }
        }

        // combine modular rho's to obtain the final rho.
        // for efficiency, first combine all pairs of small resultants to bigger resultants,
        // then combine pairs of those, etc. until only one is left.
        while (modresultants.size() > 1)
        {
            modularresultant modres1 = modresultants.removefirst();
            modularresultant modres2 = modresultants.removefirst();
            modularresultant modres3 = modularresultant.combinerho(modres1, modres2);
            modresultants.addlast(modres3);
        }
        bigintpolynomial rhop = modresultants.getfirst().rho;

        biginteger pprod2 = pprod.divide(biginteger.valueof(2));
        biginteger pprod2n = pprod2.negate();
        if (res.compareto(pprod2) > 0)
        {
            res = res.subtract(pprod);
        }
        if (res.compareto(pprod2n) < 0)
        {
            res = res.add(pprod);
        }

        for (int i = 0; i < n; i++)
        {
            biginteger c = rhop.coeffs[i];
            if (c.compareto(pprod2) > 0)
            {
                rhop.coeffs[i] = c.subtract(pprod);
            }
            if (c.compareto(pprod2n) < 0)
            {
                rhop.coeffs[i] = c.add(pprod);
            }
        }

        return new resultant(rhop, res);
    }

    /**
     * multithreaded version of {@link #resultant()}.
     *
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>.
     */
    public resultant resultantmultithread()
    {
        int n = coeffs.length;

        // upper bound for resultant(f, g) = ||f, 2||^deg(g) * ||g, 2||^deg(f) = squaresum(f)^(n/2) * 2^(deg(f)/2) because g(x)=x^n-1
        // see http://jondalon.mathematik.uni-osnabrueck.de/staff/phpages/brunsw/compalg.pdf chapter 3
        biginteger max = squaresum().pow((n + 1) / 2);
        max = max.multiply(biginteger.valueof(2).pow((degree() + 1) / 2));
        biginteger max2 = max.multiply(biginteger.valueof(2));

        // compute resultants modulo prime numbers
        biginteger prime = biginteger.valueof(10000);
        biginteger pprod = constants.bigint_one;
        linkedblockingqueue<future<modularresultant>> resultanttasks = new linkedblockingqueue<future<modularresultant>>();
        iterator<biginteger> primes = bigint_primes.iterator();
        executorservice executor = executors.newfixedthreadpool(runtime.getruntime().availableprocessors());
        while (pprod.compareto(max2) < 0)
        {
            if (primes.hasnext())
            {
                prime = primes.next();
            }
            else
            {
                prime = prime.nextprobableprime();
            }
            future<modularresultant> task = executor.submit(new modresultanttask(prime.intvalue()));
            resultanttasks.add(task);
            pprod = pprod.multiply(prime);
        }

        // combine modular resultants to obtain the resultant.
        // for efficiency, first combine all pairs of small resultants to bigger resultants,
        // then combine pairs of those, etc. until only one is left.
        modularresultant overallresultant = null;
        while (!resultanttasks.isempty())
        {
            try
            {
                future<modularresultant> modres1 = resultanttasks.take();
                future<modularresultant> modres2 = resultanttasks.poll();
                if (modres2 == null)
                {
                    // modres1 is the only one left
                    overallresultant = modres1.get();
                    break;
                }
                future<modularresultant> newtask = executor.submit(new combinetask(modres1.get(), modres2.get()));
                resultanttasks.add(newtask);
            }
            catch (exception e)
            {
                throw new illegalstateexception(e.tostring());
            }
        }
        executor.shutdown();
        biginteger res = overallresultant.res;
        bigintpolynomial rhop = overallresultant.rho;

        biginteger pprod2 = pprod.divide(biginteger.valueof(2));
        biginteger pprod2n = pprod2.negate();

        if (res.compareto(pprod2) > 0)
        {
            res = res.subtract(pprod);
        }
        if (res.compareto(pprod2n) < 0)
        {
            res = res.add(pprod);
        }

        for (int i = 0; i < n; i++)
        {
            biginteger c = rhop.coeffs[i];
            if (c.compareto(pprod2) > 0)
            {
                rhop.coeffs[i] = c.subtract(pprod);
            }
            if (c.compareto(pprod2n) < 0)
            {
                rhop.coeffs[i] = c.add(pprod);
            }
        }

        return new resultant(rhop, res);
    }

    /**
     * resultant of this polynomial with <code>x^n-1 mod p</code>.<br/>
     *
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1) mod p</code> for some integer <code>t</code>.
     */
    public modularresultant resultant(int p)
    {
        // add a coefficient as the following operations involve polynomials of degree deg(f)+1
        int[] fcoeffs = arrays.copyof(coeffs, coeffs.length + 1);
        integerpolynomial f = new integerpolynomial(fcoeffs);
        int n = fcoeffs.length;

        integerpolynomial a = new integerpolynomial(n);
        a.coeffs[0] = -1;
        a.coeffs[n - 1] = 1;
        integerpolynomial b = new integerpolynomial(f.coeffs);
        integerpolynomial v1 = new integerpolynomial(n);
        integerpolynomial v2 = new integerpolynomial(n);
        v2.coeffs[0] = 1;
        int da = n - 1;
        int db = b.degree();
        int ta = da;
        int c = 0;
        int r = 1;
        while (db > 0)
        {
            c = util.invert(b.coeffs[db], p);
            c = (c * a.coeffs[da]) % p;
            a.multshiftsub(b, c, da - db, p);
            v1.multshiftsub(v2, c, da - db, p);

            da = a.degree();
            if (da < db)
            {
                r *= util.pow(b.coeffs[db], ta - da, p);
                r %= p;
                if (ta % 2 == 1 && db % 2 == 1)
                {
                    r = (-r) % p;
                }
                integerpolynomial temp = a;
                a = b;
                b = temp;
                int tempdeg = da;
                da = db;
                temp = v1;
                v1 = v2;
                v2 = temp;
                ta = db;
                db = tempdeg;
            }
        }
        r *= util.pow(b.coeffs[0], da, p);
        r %= p;
        c = util.invert(b.coeffs[0], p);
        v2.mult(c);
        v2.mod(p);
        v2.mult(r);
        v2.mod(p);

        // drop the highest coefficient so #coeffs matches the original input
        v2.coeffs = arrays.copyof(v2.coeffs, v2.coeffs.length - 1);
        return new modularresultant(new bigintpolynomial(v2), biginteger.valueof(r), biginteger.valueof(p));
    }

    /**
     * computes <code>this-b*c*(x^k) mod p</code> and stores the result in this polynomial.<br/>
     * see steps 4a,4b in eess algorithm 2.2.7.1.
     *
     * @param b
     * @param c
     * @param k
     * @param p
     */
    private void multshiftsub(integerpolynomial b, int c, int k, int p)
    {
        int n = coeffs.length;
        for (int i = k; i < n; i++)
        {
            coeffs[i] = (coeffs[i] - b.coeffs[i - k] * c) % p;
        }
    }

    /**
     * adds the squares of all coefficients.
     *
     * @return the sum of squares
     */
    private biginteger squaresum()
    {
        biginteger sum = constants.bigint_zero;
        for (int i = 0; i < coeffs.length; i++)
        {
            sum = sum.add(biginteger.valueof(coeffs[i] * coeffs[i]));
        }
        return sum;
    }

    /**
     * returns the degree of the polynomial
     *
     * @return the degree
     */
    int degree()
    {
        int degree = coeffs.length - 1;
        while (degree > 0 && coeffs[degree] == 0)
        {
            degree--;
        }
        return degree;
    }

    /**
     * adds another polynomial which can have a different number of coefficients,
     * and takes the coefficient values mod <code>modulus</code>.
     *
     * @param b another polynomial
     */
    public void add(integerpolynomial b, int modulus)
    {
        add(b);
        mod(modulus);
    }

    /**
     * adds another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    public void add(integerpolynomial b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            coeffs = arrays.copyof(coeffs, b.coeffs.length);
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] += b.coeffs[i];
        }
    }

    /**
     * subtracts another polynomial which can have a different number of coefficients,
     * and takes the coefficient values mod <code>modulus</code>.
     *
     * @param b another polynomial
     */
    public void sub(integerpolynomial b, int modulus)
    {
        sub(b);
        mod(modulus);
    }

    /**
     * subtracts another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    public void sub(integerpolynomial b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            coeffs = arrays.copyof(coeffs, b.coeffs.length);
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] -= b.coeffs[i];
        }
    }

    /**
     * subtracts a <code>int</code> from each coefficient. does not return a new polynomial but modifies this polynomial.
     *
     * @param b
     */
    void sub(int b)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] -= b;
        }
    }

    /**
     * multiplies each coefficient by a <code>int</code>. does not return a new polynomial but modifies this polynomial.
     *
     * @param factor
     */
    public void mult(int factor)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] *= factor;
        }
    }

    /**
     * multiplies each coefficient by a 2 and applies a modulus. does not return a new polynomial but modifies this polynomial.
     *
     * @param modulus a modulus
     */
    private void mult2(int modulus)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] *= 2;
            coeffs[i] %= modulus;
        }
    }

    /**
     * multiplies each coefficient by a 2 and applies a modulus. does not return a new polynomial but modifies this polynomial.
     *
     * @param modulus a modulus
     */
    public void mult3(int modulus)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] *= 3;
            coeffs[i] %= modulus;
        }
    }

    /**
     * divides each coefficient by <code>k</code> and rounds to the nearest integer. does not return a new polynomial but modifies this polynomial.
     *
     * @param k the divisor
     */
    public void div(int k)
    {
        int k2 = (k + 1) / 2;
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] += coeffs[i] > 0 ? k2 : -k2;
            coeffs[i] /= k;
        }
    }

    /**
     * takes each coefficient modulo 3 such that all coefficients are ternary.
     */
    public void mod3()
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] %= 3;
            if (coeffs[i] > 1)
            {
                coeffs[i] -= 3;
            }
            if (coeffs[i] < -1)
            {
                coeffs[i] += 3;
            }
        }
    }

    /**
     * ensures all coefficients are between 0 and <code>modulus-1</code>
     *
     * @param modulus a modulus
     */
    public void modpositive(int modulus)
    {
        mod(modulus);
        ensurepositive(modulus);
    }

    /**
     * reduces all coefficients to the interval [-modulus/2, modulus/2)
     */
    void modcenter(int modulus)
    {
        mod(modulus);
        for (int j = 0; j < coeffs.length; j++)
        {
            while (coeffs[j] < modulus / 2)
            {
                coeffs[j] += modulus;
            }
            while (coeffs[j] >= modulus / 2)
            {
                coeffs[j] -= modulus;
            }
        }
    }

    /**
     * takes each coefficient modulo <code>modulus</code>.
     */
    public void mod(int modulus)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] %= modulus;
        }
    }

    /**
     * adds <code>modulus</code> until all coefficients are above 0.
     *
     * @param modulus a modulus
     */
    public void ensurepositive(int modulus)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            while (coeffs[i] < 0)
            {
                coeffs[i] += modulus;
            }
        }
    }

    /**
     * computes the centered euclidean norm of the polynomial.
     *
     * @param q a modulus
     * @return the centered norm
     */
    public long centerednormsq(int q)
    {
        int n = coeffs.length;
        integerpolynomial p = (integerpolynomial)clone();
        p.shiftgap(q);

        long sum = 0;
        long sqsum = 0;
        for (int i = 0; i != p.coeffs.length; i++)
        {
            int c = p.coeffs[i];
            sum += c;
            sqsum += c * c;
        }

        long centerednormsq = sqsum - sum * sum / n;
        return centerednormsq;
    }

    /**
     * shifts all coefficients so the largest gap is centered around <code>-q/2</code>.
     *
     * @param q a modulus
     */
    void shiftgap(int q)
    {
        modcenter(q);

        int[] sorted = arrays.clone(coeffs);

        sort(sorted);

        int maxrange = 0;
        int maxrangestart = 0;
        for (int i = 0; i < sorted.length - 1; i++)
        {
            int range = sorted[i + 1] - sorted[i];
            if (range > maxrange)
            {
                maxrange = range;
                maxrangestart = sorted[i];
            }
        }

        int pmin = sorted[0];
        int pmax = sorted[sorted.length - 1];

        int j = q - pmax + pmin;
        int shift;
        if (j > maxrange)
        {
            shift = (pmax + pmin) / 2;
        }
        else
        {
            shift = maxrangestart + maxrange / 2 + q / 2;
        }

        sub(shift);
    }

    private void sort(int[] ints)
    {
        boolean swap = true;

        while (swap)
        {
            swap = false;
            for (int i = 0; i != ints.length - 1; i++)
            {
                if (ints[i] > ints[i+1])
                {
                    int tmp = ints[i];
                    ints[i] = ints[i+1];
                    ints[i+1] = tmp;
                    swap = true;
                }
            }
        }
    }

    /**
     * shifts the values of all coefficients to the interval <code>[-q/2, q/2]</code>.
     *
     * @param q a modulus
     */
    public void center0(int q)
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            while (coeffs[i] < -q / 2)
            {
                coeffs[i] += q;
            }
            while (coeffs[i] > q / 2)
            {
                coeffs[i] -= q;
            }
        }
    }

    /**
     * returns the sum of all coefficients, i.e. evaluates the polynomial at 0.
     *
     * @return the sum of all coefficients
     */
    public int sumcoeffs()
    {
        int sum = 0;
        for (int i = 0; i < coeffs.length; i++)
        {
            sum += coeffs[i];
        }
        return sum;
    }

    /**
     * tests if <code>p(x) = 0</code>.
     *
     * @return true iff all coefficients are zeros
     */
    private boolean equalszero()
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            if (coeffs[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * tests if <code>p(x) = 1</code>.
     *
     * @return true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1
     */
    public boolean equalsone()
    {
        for (int i = 1; i < coeffs.length; i++)
        {
            if (coeffs[i] != 0)
            {
                return false;
            }
        }
        return coeffs[0] == 1;
    }

    /**
     * tests if <code>|p(x)| = 1</code>.
     *
     * @return true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1 or -1
     */
    private boolean equalsabsone()
    {
        for (int i = 1; i < coeffs.length; i++)
        {
            if (coeffs[i] != 0)
            {
                return false;
            }
        }
        return math.abs(coeffs[0]) == 1;
    }

    /**
     * counts the number of coefficients equal to an integer
     *
     * @param value an integer
     * @return the number of coefficients equal to <code>value</code>
     */
    public int count(int value)
    {
        int count = 0;
        for (int i = 0; i != coeffs.length; i++)
        {
            if (coeffs[i] == value)
            {
                count++;
            }
        }
        return count;
    }

    /**
     * multiplication by <code>x</code> in <code>z[x]/z[x^n-1]</code>.
     */
    public void rotate1()
    {
        int clast = coeffs[coeffs.length - 1];
        for (int i = coeffs.length - 1; i > 0; i--)
        {
            coeffs[i] = coeffs[i - 1];
        }
        coeffs[0] = clast;
    }

    public void clear()
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] = 0;
        }
    }

    public integerpolynomial tointegerpolynomial()
    {
        return (integerpolynomial)clone();
    }

    public object clone()
    {
        return new integerpolynomial(coeffs.clone());
    }

    public boolean equals(object obj)
    {
        if (obj instanceof integerpolynomial)
        {
            return arrays.areequal(coeffs, ((integerpolynomial)obj).coeffs);
        }
        else
        {
            return false;
        }
    }

    /**
     * calls {@link integerpolynomial#resultant(int)
     */
    private class modresultanttask
        implements callable<modularresultant>
    {
        private int modulus;

        private modresultanttask(int modulus)
        {
            this.modulus = modulus;
        }

        public modularresultant call()
        {
            return resultant(modulus);
        }
    }

    /**
     * calls {@link modularresultant#combinerho(modularresultant, modularresultant)
     */
    private class combinetask
        implements callable<modularresultant>
    {
        private modularresultant modres1;
        private modularresultant modres2;

        private combinetask(modularresultant modres1, modularresultant modres2)
        {
            this.modres1 = modres1;
            this.modres2 = modres2;
        }

        public modularresultant call()
        {
            return modularresultant.combinerho(modres1, modres2);
        }
    }
}
