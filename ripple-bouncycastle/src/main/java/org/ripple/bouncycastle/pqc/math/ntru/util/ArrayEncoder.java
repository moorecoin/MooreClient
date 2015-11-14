package org.ripple.bouncycastle.pqc.math.ntru.util;

import java.io.ioexception;
import java.io.inputstream;
import java.math.biginteger;

import org.ripple.bouncycastle.util.arrays;

/**
 * converts a coefficient array to a compact byte array and vice versa.
 */
public class arrayencoder
{
    /**
     * bit string to coefficient conversion table from p1363.1. also found at
     * {@link http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial}
     * <p/>
     * convert each three-bit quantity to two ternary coefficients as follows, and concatenate the resulting
     * ternary quantities to obtain [the output].
     * <p/>
     * <code>
     * {0, 0, 0} -> {0, 0}<br/>
     * {0, 0, 1} -> {0, 1}<br/>
     * {0, 1, 0} -> {0, -1}<br/>
     * {0, 1, 1} -> {1, 0}<br/>
     * {1, 0, 0} -> {1, 1}<br/>
     * {1, 0, 1} -> {1, -1}<br/>
     * {1, 1, 0} -> {-1, 0}<br/>
     * {1, 1, 1} -> {-1, 1}<br/>
     * </code>
     */
    private static final int[] coeff1_table = {0, 0, 0, 1, 1, 1, -1, -1};
    private static final int[] coeff2_table = {0, 1, -1, 0, 1, -1, 0, 1};
    /**
     * coefficient to bit string conversion table from p1363.1. also found at
     * {@link http://stackoverflow.com/questions/1562548/how-to-make-a-message-into-a-polynomial}
     * <p/>
     * convert each set of two ternary coefficients to three bits as follows, and concatenate the resulting bit
     * quantities to obtain [the output]:
     * <p/>
     * <code>
     * {-1, -1} -> set "fail" to 1 and set bit string to {1, 1, 1}
     * {-1, 0} -> {1, 1, 0}<br/>
     * {-1, 1} -> {1, 1, 1}<br/>
     * {0, -1} -> {0, 1, 0}<br/>
     * {0, 0} -> {0, 0, 0}<br/>
     * {0, 1} -> {0, 0, 1}<br/>
     * {1, -1} -> {1, 0, 1}<br/>
     * {1, 0} -> {0, 1, 1}<br/>
     * {1, 1} -> {1, 0, 0}<br/>
     * </code>
     */
    private static final int[] bit1_table = {1, 1, 1, 0, 0, 0, 1, 0, 1};
    private static final int[] bit2_table = {1, 1, 1, 1, 0, 0, 0, 1, 0};
    private static final int[] bit3_table = {1, 0, 1, 0, 0, 1, 1, 1, 0};

    /**
     * encodes an int array whose elements are between 0 and <code>q</code>,
     * to a byte array leaving no gaps between bits.<br/>
     * <code>q</code> must be a power of 2.
     *
     * @param a the input array
     * @param q the modulus
     * @return the encoded array
     */
    public static byte[] encodemodq(int[] a, int q)
    {
        int bitspercoeff = 31 - integer.numberofleadingzeros(q);
        int numbits = a.length * bitspercoeff;
        int numbytes = (numbits + 7) / 8;
        byte[] data = new byte[numbytes];
        int bitindex = 0;
        int byteindex = 0;
        for (int i = 0; i < a.length; i++)
        {
            for (int j = 0; j < bitspercoeff; j++)
            {
                int currentbit = (a[i] >> j) & 1;
                data[byteindex] |= currentbit << bitindex;
                if (bitindex == 7)
                {
                    bitindex = 0;
                    byteindex++;
                }
                else
                {
                    bitindex++;
                }
            }
        }
        return data;
    }

    /**
     * decodes a <code>byte</code> array encoded with {@link #encodemodq(int[], int)} back to an <code>int</code> array.<br/>
     * <code>n</code> is the number of coefficients. <code>q</code> must be a power of <code>2</code>.<br/>
     * ignores any excess bytes.
     *
     * @param data an encoded ternary polynomial
     * @param n    number of coefficients
     * @param q
     * @return an array containing <code>n</code> coefficients between <code>0</code> and <code>q-1</code>
     */
    public static int[] decodemodq(byte[] data, int n, int q)
    {
        int[] coeffs = new int[n];
        int bitspercoeff = 31 - integer.numberofleadingzeros(q);
        int numbits = n * bitspercoeff;
        int coeffindex = 0;
        for (int bitindex = 0; bitindex < numbits; bitindex++)
        {
            if (bitindex > 0 && bitindex % bitspercoeff == 0)
            {
                coeffindex++;
            }
            int bit = getbit(data, bitindex);
            coeffs[coeffindex] += bit << (bitindex % bitspercoeff);
        }
        return coeffs;
    }

    /**
     * decodes data encoded with {@link #encodemodq(int[], int)} back to an <code>int</code> array.<br/>
     * <code>n</code> is the number of coefficients. <code>q</code> must be a power of <code>2</code>.<br/>
     * ignores any excess bytes.
     *
     * @param is an encoded ternary polynomial
     * @param n  number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    public static int[] decodemodq(inputstream is, int n, int q)
        throws ioexception
    {
        int qbits = 31 - integer.numberofleadingzeros(q);
        int size = (n * qbits + 7) / 8;
        byte[] arr = util.readfulllength(is, size);
        return decodemodq(arr, n, q);
    }

    /**
     * decodes a <code>byte</code> array encoded with {@link #encodemod3sves(int[])} back to an <code>int</code> array
     * with <code>n</code> coefficients between <code>-1</code> and <code>1</code>.<br/>
     * ignores any excess bytes.<br/>
     * see p1363.1 section 9.2.2.
     *
     * @param data an encoded ternary polynomial
     * @param n    number of coefficients
     * @return the decoded coefficients
     */
    public static int[] decodemod3sves(byte[] data, int n)
    {
        int[] coeffs = new int[n];
        int coeffindex = 0;
        for (int bitindex = 0; bitindex < data.length * 8; )
        {
            int bit1 = getbit(data, bitindex++);
            int bit2 = getbit(data, bitindex++);
            int bit3 = getbit(data, bitindex++);
            int coefftableindex = bit1 * 4 + bit2 * 2 + bit3;
            coeffs[coeffindex++] = coeff1_table[coefftableindex];
            coeffs[coeffindex++] = coeff2_table[coefftableindex];
            // ignore bytes that can't fit
            if (coeffindex > n - 2)
            {
                break;
            }
        }
        return coeffs;
    }

    /**
     * encodes an <code>int</code> array whose elements are between <code>-1</code> and <code>1</code>, to a byte array.
     * <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer </code>i<code>,
     * so this method is only safe to use with arrays produced by {@link #decodemod3sves(byte[], int)}.<br/>
     * see p1363.1 section 9.2.3.
     *
     * @param arr
     * @return the encoded array
     */
    public static byte[] encodemod3sves(int[] arr)
    {
        int numbits = (arr.length * 3 + 1) / 2;
        int numbytes = (numbits + 7) / 8;
        byte[] data = new byte[numbytes];
        int bitindex = 0;
        int byteindex = 0;
        for (int i = 0; i < arr.length / 2 * 2; )
        {   // if length is an odd number, throw away the highest coeff
            int coeff1 = arr[i++] + 1;
            int coeff2 = arr[i++] + 1;
            if (coeff1 == 0 && coeff2 == 0)
            {
                throw new illegalstateexception("illegal encoding!");
            }
            int bittableindex = coeff1 * 3 + coeff2;
            int[] bits = new int[]{bit1_table[bittableindex], bit2_table[bittableindex], bit3_table[bittableindex]};
            for (int j = 0; j < 3; j++)
            {
                data[byteindex] |= bits[j] << bitindex;
                if (bitindex == 7)
                {
                    bitindex = 0;
                    byteindex++;
                }
                else
                {
                    bitindex++;
                }
            }
        }
        return data;
    }

    /**
     * encodes an <code>int</code> array whose elements are between <code>-1</code> and <code>1</code>, to a byte array.
     *
     * @return the encoded array
     */
    public static byte[] encodemod3tight(int[] intarray)
    {
        biginteger sum = biginteger.zero;
        for (int i = intarray.length - 1; i >= 0; i--)
        {
            sum = sum.multiply(biginteger.valueof(3));
            sum = sum.add(biginteger.valueof(intarray[i] + 1));
        }

        int size = (biginteger.valueof(3).pow(intarray.length).bitlength() + 7) / 8;
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
     * converts a byte array produced by {@link #encodemod3tight(int[])} back to an <code>int</code> array.
     *
     * @param b a byte array
     * @param n number of coefficients
     * @return the decoded array
     */
    public static int[] decodemod3tight(byte[] b, int n)
    {
        biginteger sum = new biginteger(1, b);
        int[] coeffs = new int[n];
        for (int i = 0; i < n; i++)
        {
            coeffs[i] = sum.mod(biginteger.valueof(3)).intvalue() - 1;
            if (coeffs[i] > 1)
            {
                coeffs[i] -= 3;
            }
            sum = sum.divide(biginteger.valueof(3));
        }
        return coeffs;
    }

    /**
     * converts data produced by {@link #encodemod3tight(int[])} back to an <code>int</code> array.
     *
     * @param is an input stream containing the data to decode
     * @param n  number of coefficients
     * @return the decoded array
     */
    public static int[] decodemod3tight(inputstream is, int n)
        throws ioexception
    {
        int size = (int)math.ceil(n * math.log(3) / math.log(2) / 8);
        byte[] arr = util.readfulllength(is, size);
        return decodemod3tight(arr, n);
    }

    private static int getbit(byte[] arr, int bitindex)
    {
        int byteindex = bitindex / 8;
        int arrelem = arr[byteindex] & 0xff;
        return (arrelem >> (bitindex % 8)) & 1;
    }
}