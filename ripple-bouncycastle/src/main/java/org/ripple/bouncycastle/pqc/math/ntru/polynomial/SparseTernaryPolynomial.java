package org.ripple.bouncycastle.pqc.math.ntru.polynomial;

import java.io.ioexception;
import java.io.inputstream;
import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.pqc.math.ntru.util.arrayencoder;
import org.ripple.bouncycastle.pqc.math.ntru.util.util;
import org.ripple.bouncycastle.util.arrays;

/**
 * a <code>ternarypolynomial</code> with a "low" number of nonzero coefficients.
 */
public class sparseternarypolynomial
    implements ternarypolynomial
{
    /**
     * number of bits to use for each coefficient. determines the upper bound for <code>n</code>.
     */
    private static final int bits_per_index = 11;

    private int n;
    private int[] ones;
    private int[] negones;

    /**
     * constructs a new polynomial.
     *
     * @param n       total number of coefficients including zeros
     * @param ones    indices of coefficients equal to 1
     * @param negones indices of coefficients equal to -1
     */
    sparseternarypolynomial(int n, int[] ones, int[] negones)
    {
        this.n = n;
        this.ones = ones;
        this.negones = negones;
    }

    /**
     * constructs a <code>denseternarypolynomial</code> from a <code>integerpolynomial</code>. the two polynomials are
     * independent of each other.
     *
     * @param intpoly the original polynomial
     */
    public sparseternarypolynomial(integerpolynomial intpoly)
    {
        this(intpoly.coeffs);
    }

    /**
     * constructs a new <code>sparseternarypolynomial</code> with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    public sparseternarypolynomial(int[] coeffs)
    {
        n = coeffs.length;
        ones = new int[n];
        negones = new int[n];
        int onesidx = 0;
        int negonesidx = 0;
        for (int i = 0; i < n; i++)
        {
            int c = coeffs[i];
            switch (c)
            {
            case 1:
                ones[onesidx++] = i;
                break;
            case -1:
                negones[negonesidx++] = i;
                break;
            case 0:
                break;
            default:
                throw new illegalargumentexception("illegal value: " + c + ", must be one of {-1, 0, 1}");
            }
        }
        ones = arrays.copyof(ones, onesidx);
        negones = arrays.copyof(negones, negonesidx);
    }

    /**
     * decodes a byte array encoded with {@link #tobinary()} to a ploynomial.
     *
     * @param is         an input stream containing an encoded polynomial
     * @param n          number of coefficients including zeros
     * @param numones    number of coefficients equal to 1
     * @param numnegones number of coefficients equal to -1
     * @return the decoded polynomial
     * @throws ioexception
     */
    public static sparseternarypolynomial frombinary(inputstream is, int n, int numones, int numnegones)
        throws ioexception
    {
        int maxindex = 1 << bits_per_index;
        int bitsperindex = 32 - integer.numberofleadingzeros(maxindex - 1);

        int data1len = (numones * bitsperindex + 7) / 8;
        byte[] data1 = util.readfulllength(is, data1len);
        int[] ones = arrayencoder.decodemodq(data1, numones, maxindex);

        int data2len = (numnegones * bitsperindex + 7) / 8;
        byte[] data2 = util.readfulllength(is, data2len);
        int[] negones = arrayencoder.decodemodq(data2, numnegones, maxindex);

        return new sparseternarypolynomial(n, ones, negones);
    }

    /**
     * generates a random polynomial with <code>numones</code> coefficients equal to 1,
     * <code>numnegones</code> coefficients equal to -1, and the rest equal to 0.
     *
     * @param n          number of coefficients
     * @param numones    number of 1's
     * @param numnegones number of -1's
     */
    public static sparseternarypolynomial generaterandom(int n, int numones, int numnegones, securerandom random)
    {
        int[] coeffs = util.generaterandomternary(n, numones, numnegones, random);
        return new sparseternarypolynomial(coeffs);
    }

    public integerpolynomial mult(integerpolynomial poly2)
    {
        int[] b = poly2.coeffs;
        if (b.length != n)
        {
            throw new illegalargumentexception("number of coefficients must be the same");
        }

        int[] c = new int[n];
        for (int idx = 0; idx != ones.length; idx++)
        {
            int i = ones[idx];
            int j = n - 1 - i;
            for (int k = n - 1; k >= 0; k--)
            {
                c[k] += b[j];
                j--;
                if (j < 0)
                {
                    j = n - 1;
                }
            }
        }

        for (int idx = 0; idx != negones.length; idx++)
        {
            int i = negones[idx];
            int j = n - 1 - i;
            for (int k = n - 1; k >= 0; k--)
            {
                c[k] -= b[j];
                j--;
                if (j < 0)
                {
                    j = n - 1;
                }
            }
        }

        return new integerpolynomial(c);
    }

    public integerpolynomial mult(integerpolynomial poly2, int modulus)
    {
        integerpolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }

    public bigintpolynomial mult(bigintpolynomial poly2)
    {
        biginteger[] b = poly2.coeffs;
        if (b.length != n)
        {
            throw new illegalargumentexception("number of coefficients must be the same");
        }

        biginteger[] c = new biginteger[n];
        for (int i = 0; i < n; i++)
        {
            c[i] = biginteger.zero;
        }

        for (int idx = 0; idx != ones.length; idx++)
        {
            int i = ones[idx];
            int j = n - 1 - i;
            for (int k = n - 1; k >= 0; k--)
            {
                c[k] = c[k].add(b[j]);
                j--;
                if (j < 0)
                {
                    j = n - 1;
                }
            }
        }

        for (int idx = 0; idx != negones.length; idx++)
        {
            int i = negones[idx];
            int j = n - 1 - i;
            for (int k = n - 1; k >= 0; k--)
            {
                c[k] = c[k].subtract(b[j]);
                j--;
                if (j < 0)
                {
                    j = n - 1;
                }
            }
        }

        return new bigintpolynomial(c);
    }

    public int[] getones()
    {
        return ones;
    }

    public int[] getnegones()
    {
        return negones;
    }

    /**
     * encodes the polynomial to a byte array writing <code>bits_per_index</code> bits for each coefficient.
     *
     * @return the encoded polynomial
     */
    public byte[] tobinary()
    {
        int maxindex = 1 << bits_per_index;
        byte[] bin1 = arrayencoder.encodemodq(ones, maxindex);
        byte[] bin2 = arrayencoder.encodemodq(negones, maxindex);

        byte[] bin = arrays.copyof(bin1, bin1.length + bin2.length);
        system.arraycopy(bin2, 0, bin, bin1.length, bin2.length);
        return bin;
    }

    public integerpolynomial tointegerpolynomial()
    {
        int[] coeffs = new int[n];
        for (int idx = 0; idx != ones.length; idx++)
        {
            int i = ones[idx];
            coeffs[i] = 1;
        }
        for (int idx = 0; idx != negones.length; idx++)
        {
            int i = negones[idx];
            coeffs[i] = -1;
        }
        return new integerpolynomial(coeffs);
    }

    public int size()
    {
        return n;
    }

    public void clear()
    {
        for (int i = 0; i < ones.length; i++)
        {
            ones[i] = 0;
        }
        for (int i = 0; i < negones.length; i++)
        {
            negones[i] = 0;
        }
    }

    public int hashcode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + n;
        result = prime * result + arrays.hashcode(negones);
        result = prime * result + arrays.hashcode(ones);
        return result;
    }

    public boolean equals(object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (getclass() != obj.getclass())
        {
            return false;
        }
        sparseternarypolynomial other = (sparseternarypolynomial)obj;
        if (n != other.n)
        {
            return false;
        }
        if (!arrays.areequal(negones, other.negones))
        {
            return false;
        }
        if (!arrays.areequal(ones, other.ones))
        {
            return false;
        }
        return true;
    }
}
