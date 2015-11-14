package org.ripple.bouncycastle.pqc.math.linearalgebra;


/**
 * this is a utility class containing data type conversions using big-endian
 * byte order.
 *
 * @see littleendianconversions
 */
public final class bigendianconversions
{

    /**
     * default constructor (private).
     */
    private bigendianconversions()
    {
        // empty
    }

    /**
     * convert an integer to an octet string of length 4 according to ieee 1363,
     * section 5.5.3.
     *
     * @param x the integer to convert
     * @return the converted integer
     */
    public static byte[] i2osp(int x)
    {
        byte[] result = new byte[4];
        result[0] = (byte)(x >>> 24);
        result[1] = (byte)(x >>> 16);
        result[2] = (byte)(x >>> 8);
        result[3] = (byte)x;
        return result;
    }

    /**
     * convert an integer to an octet string according to ieee 1363, section
     * 5.5.3. length checking is performed.
     *
     * @param x    the integer to convert
     * @param olen the desired length of the octet string
     * @return an octet string of length <tt>olen</tt> representing the
     *         integer <tt>x</tt>, or <tt>null</tt> if the integer is
     *         negative
     * @throws arithmeticexception if <tt>x</tt> can't be encoded into <tt>olen</tt>
     * octets.
     */
    public static byte[] i2osp(int x, int olen)
        throws arithmeticexception
    {
        if (x < 0)
        {
            return null;
        }
        int octl = integerfunctions.ceillog256(x);
        if (octl > olen)
        {
            throw new arithmeticexception(
                "cannot encode given integer into specified number of octets.");
        }
        byte[] result = new byte[olen];
        for (int i = olen - 1; i >= olen - octl; i--)
        {
            result[i] = (byte)(x >>> (8 * (olen - 1 - i)));
        }
        return result;
    }

    /**
     * convert an integer to an octet string of length 4 according to ieee 1363,
     * section 5.5.3.
     *
     * @param input  the integer to convert
     * @param output byte array holding the output
     * @param outoff offset in output array where the result is stored
     */
    public static void i2osp(int input, byte[] output, int outoff)
    {
        output[outoff++] = (byte)(input >>> 24);
        output[outoff++] = (byte)(input >>> 16);
        output[outoff++] = (byte)(input >>> 8);
        output[outoff] = (byte)input;
    }

    /**
     * convert an integer to an octet string of length 8 according to ieee 1363,
     * section 5.5.3.
     *
     * @param input the integer to convert
     * @return the converted integer
     */
    public static byte[] i2osp(long input)
    {
        byte[] output = new byte[8];
        output[0] = (byte)(input >>> 56);
        output[1] = (byte)(input >>> 48);
        output[2] = (byte)(input >>> 40);
        output[3] = (byte)(input >>> 32);
        output[4] = (byte)(input >>> 24);
        output[5] = (byte)(input >>> 16);
        output[6] = (byte)(input >>> 8);
        output[7] = (byte)input;
        return output;
    }

    /**
     * convert an integer to an octet string of length 8 according to ieee 1363,
     * section 5.5.3.
     *
     * @param input  the integer to convert
     * @param output byte array holding the output
     * @param outoff offset in output array where the result is stored
     */
    public static void i2osp(long input, byte[] output, int outoff)
    {
        output[outoff++] = (byte)(input >>> 56);
        output[outoff++] = (byte)(input >>> 48);
        output[outoff++] = (byte)(input >>> 40);
        output[outoff++] = (byte)(input >>> 32);
        output[outoff++] = (byte)(input >>> 24);
        output[outoff++] = (byte)(input >>> 16);
        output[outoff++] = (byte)(input >>> 8);
        output[outoff] = (byte)input;
    }

    /**
     * convert an integer to an octet string of the specified length according
     * to ieee 1363, section 5.5.3. no length checking is performed (i.e., if
     * the integer cannot be encoded into <tt>length</tt> octets, it is
     * truncated).
     *
     * @param input  the integer to convert
     * @param output byte array holding the output
     * @param outoff offset in output array where the result is stored
     * @param length the length of the encoding
     */
    public static void i2osp(int input, byte[] output, int outoff, int length)
    {
        for (int i = length - 1; i >= 0; i--)
        {
            output[outoff + i] = (byte)(input >>> (8 * (length - 1 - i)));
        }
    }

    /**
     * convert an octet string to an integer according to ieee 1363, section
     * 5.5.3.
     *
     * @param input the byte array holding the octet string
     * @return an integer representing the octet string <tt>input</tt>, or
     *         <tt>0</tt> if the represented integer is negative or too large
     *         or the byte array is empty
     * @throws arithmeticexception if the length of the given octet string is larger than 4.
     */
    public static int os2ip(byte[] input)
    {
        if (input.length > 4)
        {
            throw new arithmeticexception("invalid input length");
        }
        if (input.length == 0)
        {
            return 0;
        }
        int result = 0;
        for (int j = 0; j < input.length; j++)
        {
            result |= (input[j] & 0xff) << (8 * (input.length - 1 - j));
        }
        return result;
    }

    /**
     * convert a byte array of length 4 beginning at <tt>offset</tt> into an
     * integer.
     *
     * @param input the byte array
     * @param inoff the offset into the byte array
     * @return the resulting integer
     */
    public static int os2ip(byte[] input, int inoff)
    {
        int result = (input[inoff++] & 0xff) << 24;
        result |= (input[inoff++] & 0xff) << 16;
        result |= (input[inoff++] & 0xff) << 8;
        result |= input[inoff] & 0xff;
        return result;
    }

    /**
     * convert an octet string to an integer according to ieee 1363, section
     * 5.5.3.
     *
     * @param input the byte array holding the octet string
     * @param inoff the offset in the input byte array where the octet string
     *              starts
     * @param inlen the length of the encoded integer
     * @return an integer representing the octet string <tt>bytes</tt>, or
     *         <tt>0</tt> if the represented integer is negative or too large
     *         or the byte array is empty
     */
    public static int os2ip(byte[] input, int inoff, int inlen)
    {
        if ((input.length == 0) || input.length < inoff + inlen - 1)
        {
            return 0;
        }
        int result = 0;
        for (int j = 0; j < inlen; j++)
        {
            result |= (input[inoff + j] & 0xff) << (8 * (inlen - j - 1));
        }
        return result;
    }

    /**
     * convert a byte array of length 8 beginning at <tt>inoff</tt> into a
     * long integer.
     *
     * @param input the byte array
     * @param inoff the offset into the byte array
     * @return the resulting long integer
     */
    public static long os2lip(byte[] input, int inoff)
    {
        long result = ((long)input[inoff++] & 0xff) << 56;
        result |= ((long)input[inoff++] & 0xff) << 48;
        result |= ((long)input[inoff++] & 0xff) << 40;
        result |= ((long)input[inoff++] & 0xff) << 32;
        result |= ((long)input[inoff++] & 0xff) << 24;
        result |= (input[inoff++] & 0xff) << 16;
        result |= (input[inoff++] & 0xff) << 8;
        result |= input[inoff] & 0xff;
        return result;
    }

    /**
     * convert an int array into a byte array.
     *
     * @param input the int array
     * @return the converted array
     */
    public static byte[] tobytearray(final int[] input)
    {
        byte[] result = new byte[input.length << 2];
        for (int i = 0; i < input.length; i++)
        {
            i2osp(input[i], result, i << 2);
        }
        return result;
    }

    /**
     * convert an int array into a byte array of the specified length. no length
     * checking is performed (i.e., if the last integer cannot be encoded into
     * <tt>length % 4</tt> octets, it is truncated).
     *
     * @param input  the int array
     * @param length the length of the converted array
     * @return the converted array
     */
    public static byte[] tobytearray(final int[] input, int length)
    {
        final int intlen = input.length;
        byte[] result = new byte[length];
        int index = 0;
        for (int i = 0; i <= intlen - 2; i++, index += 4)
        {
            i2osp(input[i], result, index);
        }
        i2osp(input[intlen - 1], result, index, length - index);
        return result;
    }

    /**
     * convert a byte array into an int array.
     *
     * @param input the byte array
     * @return the converted array
     */
    public static int[] tointarray(byte[] input)
    {
        final int intlen = (input.length + 3) / 4;
        final int lastlen = input.length & 0x03;
        int[] result = new int[intlen];

        int index = 0;
        for (int i = 0; i <= intlen - 2; i++, index += 4)
        {
            result[i] = os2ip(input, index);
        }
        if (lastlen != 0)
        {
            result[intlen - 1] = os2ip(input, index, lastlen);
        }
        else
        {
            result[intlen - 1] = os2ip(input, index);
        }

        return result;
    }

}
