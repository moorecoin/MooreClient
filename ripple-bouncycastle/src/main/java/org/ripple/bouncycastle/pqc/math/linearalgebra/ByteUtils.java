package org.ripple.bouncycastle.pqc.math.linearalgebra;

/**
 * this class is a utility class for manipulating byte arrays.
 */
public final class byteutils
{

    private static final char[] hex_chars = {'0', '1', '2', '3', '4', '5',
        '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * default constructor (private)
     */
    private byteutils()
    {
        // empty
    }

    /**
     * compare two byte arrays (perform null checks beforehand).
     *
     * @param left  the first byte array
     * @param right the second byte array
     * @return the result of the comparison
     */
    public static boolean equals(byte[] left, byte[] right)
    {
        if (left == null)
        {
            return right == null;
        }
        if (right == null)
        {
            return false;
        }

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
     * compare two two-dimensional byte arrays. no null checks are performed.
     *
     * @param left  the first byte array
     * @param right the second byte array
     * @return the result of the comparison
     */
    public static boolean equals(byte[][] left, byte[][] right)
    {
        if (left.length != right.length)
        {
            return false;
        }

        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            result &= byteutils.equals(left[i], right[i]);
        }

        return result;
    }

    /**
     * compare two three-dimensional byte arrays. no null checks are performed.
     *
     * @param left  the first byte array
     * @param right the second byte array
     * @return the result of the comparison
     */
    public static boolean equals(byte[][][] left, byte[][][] right)
    {
        if (left.length != right.length)
        {
            return false;
        }

        boolean result = true;
        for (int i = left.length - 1; i >= 0; i--)
        {
            if (left[i].length != right[i].length)
            {
                return false;
            }
            for (int j = left[i].length - 1; j >= 0; j--)
            {
                result &= byteutils.equals(left[i][j], right[i][j]);
            }
        }

        return result;
    }

    /**
     * computes a hashcode based on the contents of a one-dimensional byte array
     * rather than its identity.
     *
     * @param array the array to compute the hashcode of
     * @return the hashcode
     */
    public static int deephashcode(byte[] array)
    {
        int result = 1;
        for (int i = 0; i < array.length; i++)
        {
            result = 31 * result + array[i];
        }
        return result;
    }

    /**
     * computes a hashcode based on the contents of a two-dimensional byte array
     * rather than its identity.
     *
     * @param array the array to compute the hashcode of
     * @return the hashcode
     */
    public static int deephashcode(byte[][] array)
    {
        int result = 1;
        for (int i = 0; i < array.length; i++)
        {
            result = 31 * result + deephashcode(array[i]);
        }
        return result;
    }

    /**
     * computes a hashcode based on the contents of a three-dimensional byte
     * array rather than its identity.
     *
     * @param array the array to compute the hashcode of
     * @return the hashcode
     */
    public static int deephashcode(byte[][][] array)
    {
        int result = 1;
        for (int i = 0; i < array.length; i++)
        {
            result = 31 * result + deephashcode(array[i]);
        }
        return result;
    }


    /**
     * return a clone of the given byte array (performs null check beforehand).
     *
     * @param array the array to clone
     * @return the clone of the given array, or <tt>null</tt> if the array is
     *         <tt>null</tt>
     */
    public static byte[] clone(byte[] array)
    {
        if (array == null)
        {
            return null;
        }
        byte[] result = new byte[array.length];
        system.arraycopy(array, 0, result, 0, array.length);
        return result;
    }

    /**
     * convert a string containing hexadecimal characters to a byte-array.
     *
     * @param s a hex string
     * @return a byte array with the corresponding value
     */
    public static byte[] fromhexstring(string s)
    {
        char[] rawchars = s.touppercase().tochararray();

        int hexchars = 0;
        for (int i = 0; i < rawchars.length; i++)
        {
            if ((rawchars[i] >= '0' && rawchars[i] <= '9')
                || (rawchars[i] >= 'a' && rawchars[i] <= 'f'))
            {
                hexchars++;
            }
        }

        byte[] bytestring = new byte[(hexchars + 1) >> 1];

        int pos = hexchars & 1;

        for (int i = 0; i < rawchars.length; i++)
        {
            if (rawchars[i] >= '0' && rawchars[i] <= '9')
            {
                bytestring[pos >> 1] <<= 4;
                bytestring[pos >> 1] |= rawchars[i] - '0';
            }
            else if (rawchars[i] >= 'a' && rawchars[i] <= 'f')
            {
                bytestring[pos >> 1] <<= 4;
                bytestring[pos >> 1] |= rawchars[i] - 'a' + 10;
            }
            else
            {
                continue;
            }
            pos++;
        }

        return bytestring;
    }

    /**
     * convert a byte array to the corresponding hexstring.
     *
     * @param input the byte array to be converted
     * @return the corresponding hexstring
     */
    public static string tohexstring(byte[] input)
    {
        string result = "";
        for (int i = 0; i < input.length; i++)
        {
            result += hex_chars[(input[i] >>> 4) & 0x0f];
            result += hex_chars[(input[i]) & 0x0f];
        }
        return result;
    }

    /**
     * convert a byte array to the corresponding hex string.
     *
     * @param input     the byte array to be converted
     * @param prefix    the prefix to put at the beginning of the hex string
     * @param seperator a separator string
     * @return the corresponding hex string
     */
    public static string tohexstring(byte[] input, string prefix,
                                     string seperator)
    {
        string result = new string(prefix);
        for (int i = 0; i < input.length; i++)
        {
            result += hex_chars[(input[i] >>> 4) & 0x0f];
            result += hex_chars[(input[i]) & 0x0f];
            if (i < input.length - 1)
            {
                result += seperator;
            }
        }
        return result;
    }

    /**
     * convert a byte array to the corresponding bit string.
     *
     * @param input the byte array to be converted
     * @return the corresponding bit string
     */
    public static string tobinarystring(byte[] input)
    {
        string result = "";
        int i;
        for (i = 0; i < input.length; i++)
        {
            int e = input[i];
            for (int ii = 0; ii < 8; ii++)
            {
                int b = (e >>> ii) & 1;
                result += b;
            }
            if (i != input.length - 1)
            {
                result += " ";
            }
        }
        return result;
    }

    /**
     * compute the bitwise xor of two arrays of bytes. the arrays have to be of
     * same length. no length checking is performed.
     *
     * @param x1 the first array
     * @param x2 the second array
     * @return x1 xor x2
     */
    public static byte[] xor(byte[] x1, byte[] x2)
    {
        byte[] out = new byte[x1.length];

        for (int i = x1.length - 1; i >= 0; i--)
        {
            out[i] = (byte)(x1[i] ^ x2[i]);
        }
        return out;
    }

    /**
     * concatenate two byte arrays. no null checks are performed.
     *
     * @param x1 the first array
     * @param x2 the second array
     * @return (x2||x1) (little-endian order, i.e. x1 is at lower memory
     *         addresses)
     */
    public static byte[] concatenate(byte[] x1, byte[] x2)
    {
        byte[] result = new byte[x1.length + x2.length];

        system.arraycopy(x1, 0, result, 0, x1.length);
        system.arraycopy(x2, 0, result, x1.length, x2.length);

        return result;
    }

    /**
     * convert a 2-dimensional byte array into a 1-dimensional byte array by
     * concatenating all entries.
     *
     * @param array a 2-dimensional byte array
     * @return the concatenated input array
     */
    public static byte[] concatenate(byte[][] array)
    {
        int rowlength = array[0].length;
        byte[] result = new byte[array.length * rowlength];
        int index = 0;
        for (int i = 0; i < array.length; i++)
        {
            system.arraycopy(array[i], 0, result, index, rowlength);
            index += rowlength;
        }
        return result;
    }

    /**
     * split a byte array <tt>input</tt> into two arrays at <tt>index</tt>,
     * i.e. the first array will have the lower <tt>index</tt> bytes, the
     * second one the higher <tt>input.length - index</tt> bytes.
     *
     * @param input the byte array to be split
     * @param index the index where the byte array is split
     * @return the splitted input array as an array of two byte arrays
     * @throws arrayindexoutofboundsexception if <tt>index</tt> is out of bounds
     */
    public static byte[][] split(byte[] input, int index)
        throws arrayindexoutofboundsexception
    {
        if (index > input.length)
        {
            throw new arrayindexoutofboundsexception();
        }
        byte[][] result = new byte[2][];
        result[0] = new byte[index];
        result[1] = new byte[input.length - index];
        system.arraycopy(input, 0, result[0], 0, index);
        system.arraycopy(input, index, result[1], 0, input.length - index);
        return result;
    }

    /**
     * generate a subarray of a given byte array.
     *
     * @param input the input byte array
     * @param start the start index
     * @param end   the end index
     * @return a subarray of <tt>input</tt>, ranging from <tt>start</tt>
     *         (inclusively) to <tt>end</tt> (exclusively)
     */
    public static byte[] subarray(byte[] input, int start, int end)
    {
        byte[] result = new byte[end - start];
        system.arraycopy(input, start, result, 0, end - start);
        return result;
    }

    /**
     * generate a subarray of a given byte array.
     *
     * @param input the input byte array
     * @param start the start index
     * @return a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
     *         the end of the array
     */
    public static byte[] subarray(byte[] input, int start)
    {
        return subarray(input, start, input.length);
    }

    /**
     * rewrite a byte array as a char array
     *
     * @param input -
     *              the byte array
     * @return char array
     */
    public static char[] tochararray(byte[] input)
    {
        char[] result = new char[input.length];
        for (int i = 0; i < input.length; i++)
        {
            result[i] = (char)input[i];
        }
        return result;
    }

}
