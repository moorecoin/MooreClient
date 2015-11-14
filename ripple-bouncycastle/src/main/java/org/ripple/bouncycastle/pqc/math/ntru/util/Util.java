package org.ripple.bouncycastle.pqc.math.ntru.util;

import java.io.ioexception;
import java.io.inputstream;
import java.security.securerandom;
import java.util.arraylist;
import java.util.collections;
import java.util.list;

import org.ripple.bouncycastle.pqc.math.ntru.euclid.inteuclidean;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.denseternarypolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.sparseternarypolynomial;
import org.ripple.bouncycastle.pqc.math.ntru.polynomial.ternarypolynomial;
import org.ripple.bouncycastle.util.integers;

public class util
{
    private static volatile boolean is_64_bitness_known;
    private static volatile boolean is_64_bit_jvm;

    /**
     * calculates the inverse of n mod modulus
     */
    public static int invert(int n, int modulus)
    {
        n %= modulus;
        if (n < 0)
        {
            n += modulus;
        }
        return inteuclidean.calculate(n, modulus).x;
    }

    /**
     * calculates a^b mod modulus
     */
    public static int pow(int a, int b, int modulus)
    {
        int p = 1;
        for (int i = 0; i < b; i++)
        {
            p = (p * a) % modulus;
        }
        return p;
    }

    /**
     * calculates a^b mod modulus
     */
    public static long pow(long a, int b, long modulus)
    {
        long p = 1;
        for (int i = 0; i < b; i++)
        {
            p = (p * a) % modulus;
        }
        return p;
    }

    /**
     * generates a "sparse" or "dense" polynomial containing numones ints equal to 1,
     * numnegones int equal to -1, and the rest equal to 0.
     *
     * @param n
     * @param numones
     * @param numnegones
     * @param sparse     whether to create a {@link sparseternarypolynomial} or {@link denseternarypolynomial}
     * @return a ternary polynomial
     */
    public static ternarypolynomial generaterandomternary(int n, int numones, int numnegones, boolean sparse, securerandom random)
    {
        if (sparse)
        {
            return sparseternarypolynomial.generaterandom(n, numones, numnegones, random);
        }
        else
        {
            return denseternarypolynomial.generaterandom(n, numones, numnegones, random);
        }
    }

    /**
     * generates an array containing numones ints equal to 1,
     * numnegones int equal to -1, and the rest equal to 0.
     *
     * @param n
     * @param numones
     * @param numnegones
     * @return an array of integers
     */
    public static int[] generaterandomternary(int n, int numones, int numnegones, securerandom random)
    {
        integer one = integers.valueof(1);
        integer minusone = integers.valueof(-1);
        integer zero = integers.valueof(0);

        list list = new arraylist();
        for (int i = 0; i < numones; i++)
        {
            list.add(one);
        }
        for (int i = 0; i < numnegones; i++)
        {
            list.add(minusone);
        }
        while (list.size() < n)
        {
            list.add(zero);
        }

        collections.shuffle(list, random);

        int[] arr = new int[n];
        for (int i = 0; i < n; i++)
        {
            arr[i] = ((integer)list.get(i)).intvalue();
        }
        return arr;
    }

    /**
     * takes an educated guess as to whether 64 bits are supported by the jvm.
     *
     * @return <code>true</code> if 64-bit support detected, <code>false</code> otherwise
     */
    public static boolean is64bitjvm()
    {
        if (!is_64_bitness_known)
        {
            string arch = system.getproperty("os.arch");
            string sunmodel = system.getproperty("sun.arch.data.model");
            is_64_bit_jvm = "amd64".equals(arch) || "x86_64".equals(arch) || "ppc64".equals(arch) || "64".equals(sunmodel);
            is_64_bitness_known = true;
        }
        return is_64_bit_jvm;
    }

    /**
     * reads a given number of bytes from an <code>inputstream</code>.
     * if there are not enough bytes in the stream, an <code>ioexception</code>
     * is thrown.
     *
     * @param is
     * @param length
     * @return an array of length <code>length</code>
     * @throws ioexception
     */
    public static byte[] readfulllength(inputstream is, int length)
        throws ioexception
    {
        byte[] arr = new byte[length];
        if (is.read(arr) != arr.length)
        {
            throw new ioexception("not enough bytes to read.");
        }
        return arr;
    }
}