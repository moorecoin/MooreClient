package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.math.biginteger;

/**
 * fixme: is this really necessary?!
 */
public final class bigintutils
{

    /**
     * default constructor (private).
     */
    private bigintutils()
    {
        // empty
    }

    /**
     * checks if two biginteger arrays contain the same entries
     *
     * @param a first biginteger array
     * @param b second biginteger array
     * @return true or false
     */
    public static boolean equals(biginteger[] a, biginteger[] b)
    {
        int flag = 0;

        if (a.length != b.length)
        {
            return false;
        }
        for (int i = 0; i < a.length; i++)
        {
            // avoid branches here!
            // problem: compareto on bigintegers is not
            // guaranteed constant-time!
            flag |= a[i].compareto(b[i]);
        }
        return flag == 0;
    }

    /**
     * fill the given biginteger array with the given value.
     *
     * @param array the array
     * @param value the value
     */
    public static void fill(biginteger[] array, biginteger value)
    {
        for (int i = array.length - 1; i >= 0; i--)
        {
            array[i] = value;
        }
    }

    /**
     * generates a subarray of a given biginteger array.
     *
     * @param input -
     *              the input biginteger array
     * @param start -
     *              the start index
     * @param end   -
     *              the end index
     * @return a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
     *         <tt>end</tt>
     */
    public static biginteger[] subarray(biginteger[] input, int start, int end)
    {
        biginteger[] result = new biginteger[end - start];
        system.arraycopy(input, start, result, 0, end - start);
        return result;
    }

    /**
     * converts a biginteger array into an integer array
     *
     * @param input -
     *              the biginteger array
     * @return the integer array
     */
    public static int[] tointarray(biginteger[] input)
    {
        int[] result = new int[input.length];
        for (int i = 0; i < input.length; i++)
        {
            result[i] = input[i].intvalue();
        }
        return result;
    }

    /**
     * converts a biginteger array into an integer array, reducing all
     * bigintegers mod q.
     *
     * @param q     -
     *              the modulus
     * @param input -
     *              the biginteger array
     * @return the integer array
     */
    public static int[] tointarraymodq(int q, biginteger[] input)
    {
        biginteger bq = biginteger.valueof(q);
        int[] result = new int[input.length];
        for (int i = 0; i < input.length; i++)
        {
            result[i] = input[i].mod(bq).intvalue();
        }
        return result;
    }

    /**
     * return the value of <tt>big</tt> as a byte array. although biginteger
     * has such a method, it uses an extra bit to indicate the sign of the
     * number. for elliptic curve cryptography, the numbers usually are
     * positive. thus, this helper method returns a byte array of minimal
     * length, ignoring the sign of the number.
     *
     * @param value the <tt>biginteger</tt> value to be converted to a byte
     *              array
     * @return the value <tt>big</tt> as byte array
     */
    public static byte[] tominimalbytearray(biginteger value)
    {
        byte[] valbytes = value.tobytearray();
        if ((valbytes.length == 1) || (value.bitlength() & 0x07) != 0)
        {
            return valbytes;
        }
        byte[] result = new byte[value.bitlength() >> 3];
        system.arraycopy(valbytes, 1, result, 0, result.length);
        return result;
    }

}
