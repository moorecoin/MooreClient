package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.math.biginteger;

/**
 *
 *
 *
 */
public final class intutils
{

    /**
     * default constructor (private).
     */
    private intutils()
    {
        // empty
    }

    /**
     * compare two int arrays. no null checks are performed.
     *
     * @param left  the first int array
     * @param right the second int array
     * @return the result of the comparison
     */
    public static boolean equals(int[] left, int[] right)
    {
        if (left.length != right.length)
        {
            return false;
        }
        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= left[i] == right[i];
        }
        return result;
    }

    /**
     * return a clone of the given int array. no null checks are performed.
     *
     * @param array the array to clone
     * @return the clone of the given array
     */
    public static int[] clone(int[] array)
    {
        int[] result = new int[array.length];
        system.arraycopy(array, 0, result, 0, array.length);
        return result;
    }

    /**
     * fill the given int array with the given value.
     *
     * @param array the array
     * @param value the value
     */
    public static void fill(int[] array, int value)
    {
        for (int i = array.length - 1; i >= 0; i--)
        {
            array[i] = value;
        }
    }

    /**
     * sorts this array of integers according to the quicksort algorithm. after
     * calling this method this array is sorted in ascending order with the
     * smallest integer taking position 0 in the array.
     * <p/>
     * <p/>
     * this implementation is based on the quicksort algorithm as described in
     * <code>data structures in java</code> by thomas a. standish, chapter 10,
     * isbn 0-201-30564-x.
     *
     * @param source the array of integers that needs to be sorted.
     */
    public static void quicksort(int[] source)
    {
        quicksort(source, 0, source.length - 1);
    }

    /**
     * sort a subarray of a source array. the subarray is specified by its start
     * and end index.
     *
     * @param source the int array to be sorted
     * @param left   the start index of the subarray
     * @param right  the end index of the subarray
     */
    public static void quicksort(int[] source, int left, int right)
    {
        if (right > left)
        {
            int index = partition(source, left, right, right);
            quicksort(source, left, index - 1);
            quicksort(source, index + 1, right);
        }
    }

    /**
     * split a subarray of a source array into two partitions. the left
     * partition contains elements that have value less than or equal to the
     * pivot element, the right partition contains the elements that have larger
     * value.
     *
     * @param source     the int array whose subarray will be splitted
     * @param left       the start position of the subarray
     * @param right      the end position of the subarray
     * @param pivotindex the index of the pivot element inside the array
     * @return the new index of the pivot element inside the array
     */
    private static int partition(int[] source, int left, int right,
                                 int pivotindex)
    {

        int pivot = source[pivotindex];
        source[pivotindex] = source[right];
        source[right] = pivot;

        int index = left;

        for (int i = left; i < right; i++)
        {
            if (source[i] <= pivot)
            {
                int tmp = source[index];
                source[index] = source[i];
                source[i] = tmp;
                index++;
            }
        }

        int tmp = source[index];
        source[index] = source[right];
        source[right] = tmp;

        return index;
    }

    /**
     * generates a subarray of a given int array.
     *
     * @param input -
     *              the input int array
     * @param start -
     *              the start index
     * @param end   -
     *              the end index
     * @return a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
     *         <tt>end</tt>
     */
    public static int[] subarray(final int[] input, final int start,
                                 final int end)
    {
        int[] result = new int[end - start];
        system.arraycopy(input, start, result, 0, end - start);
        return result;
    }

    /**
     * convert an int array to a {@link flexibigint} array.
     *
     * @param input the int array
     * @return the {@link flexibigint} array
     */
    public static biginteger[] toflexibigintarray(int[] input)
    {
        biginteger[] result = new biginteger[input.length];
        for (int i = 0; i < input.length; i++)
        {
            result[i] = biginteger.valueof(input[i]);
        }
        return result;
    }

    /**
     * @param input an int array
     * @return a human readable form of the given int array
     */
    public static string tostring(int[] input)
    {
        string result = "";
        for (int i = 0; i < input.length; i++)
        {
            result += input[i] + " ";
        }
        return result;
    }

    /**
     * @param input an int arary
     * @return the int array as hex string
     */
    public static string tohexstring(int[] input)
    {
        return byteutils.tohexstring(bigendianconversions.tobytearray(input));
    }

}
