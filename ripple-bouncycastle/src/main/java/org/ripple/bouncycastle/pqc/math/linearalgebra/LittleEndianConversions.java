package org.ripple.bouncycastle.pqc.math.linearalgebra;

/**
 * this is a utility class containing data type conversions using little-endian
 * byte order.
 *
 * @see bigendianconversions
 */
public final class littleendianconversions
{

    /**
     * default constructor (private).
     */
    private littleendianconversions()
    {
        // empty
    }

    /**
     * convert an octet string of length 4 to an integer. no length checking is
     * performed.
     *
     * @param input the byte array holding the octet string
     * @return an integer representing the octet string <tt>input</tt>
     * @throws arithmeticexception if the length of the given octet string is larger than 4.
     */
    public static int os2ip(byte[] input)
    {
        return ((input[0] & 0xff)) | ((input[1] & 0xff) << 8)
            | ((input[2] & 0xff) << 16) | ((input[3] & 0xff)) << 24;
    }

    /**
     * convert an byte array of length 4 beginning at <tt>offset</tt> into an
     * integer.
     *
     * @param input the byte array
     * @param inoff the offset into the byte array
     * @return the resulting integer
     */
    public static int os2ip(byte[] input, int inoff)
    {
        int result = input[inoff++] & 0xff;
        result |= (input[inoff++] & 0xff) << 8;
        result |= (input[inoff++] & 0xff) << 16;
        result |= (input[inoff] & 0xff) << 24;
        return result;
    }

    /**
     * convert a byte array of the given length beginning at <tt>offset</tt>
     * into an integer.
     *
     * @param input the byte array
     * @param inoff the offset into the byte array
     * @param inlen the length of the encoding
     * @return the resulting integer
     */
    public static int os2ip(byte[] input, int inoff, int inlen)
    {
        int result = 0;
        for (int i = inlen - 1; i >= 0; i--)
        {
            result |= (input[inoff + i] & 0xff) << (8 * i);
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
        long result = input[inoff++] & 0xff;
        result |= (input[inoff++] & 0xff) << 8;
        result |= (input[inoff++] & 0xff) << 16;
        result |= ((long)input[inoff++] & 0xff) << 24;
        result |= ((long)input[inoff++] & 0xff) << 32;
        result |= ((long)input[inoff++] & 0xff) << 40;
        result |= ((long)input[inoff++] & 0xff) << 48;
        result |= ((long)input[inoff++] & 0xff) << 56;
        return result;
    }

    /**
     * convert an integer to an octet string of length 4.
     *
     * @param x the integer to convert
     * @return the converted integer
     */
    public static byte[] i2osp(int x)
    {
        byte[] result = new byte[4];
        result[0] = (byte)x;
        result[1] = (byte)(x >>> 8);
        result[2] = (byte)(x >>> 16);
        result[3] = (byte)(x >>> 24);
        return result;
    }

    /**
     * convert an integer into a byte array beginning at the specified offset.
     *
     * @param value  the integer to convert
     * @param output the byte array to hold the result
     * @param outoff the integer offset into the byte array
     */
    public static void i2osp(int value, byte[] output, int outoff)
    {
        output[outoff++] = (byte)value;
        output[outoff++] = (byte)(value >>> 8);
        output[outoff++] = (byte)(value >>> 16);
        output[outoff++] = (byte)(value >>> 24);
    }

    /**
     * convert an integer to a byte array beginning at the specified offset. no
     * length checking is performed (i.e., if the integer cannot be encoded with
     * <tt>length</tt> octets, it is truncated).
     *
     * @param value  the integer to convert
     * @param output the byte array to hold the result
     * @param outoff the integer offset into the byte array
     * @param outlen the length of the encoding
     */
    public static void i2osp(int value, byte[] output, int outoff, int outlen)
    {
        for (int i = outlen - 1; i >= 0; i--)
        {
            output[outoff + i] = (byte)(value >>> (8 * i));
        }
    }

    /**
     * convert an integer to a byte array of length 8.
     *
     * @param input the integer to convert
     * @return the converted integer
     */
    public static byte[] i2osp(long input)
    {
        byte[] output = new byte[8];
        output[0] = (byte)input;
        output[1] = (byte)(input >>> 8);
        output[2] = (byte)(input >>> 16);
        output[3] = (byte)(input >>> 24);
        output[4] = (byte)(input >>> 32);
        output[5] = (byte)(input >>> 40);
        output[6] = (byte)(input >>> 48);
        output[7] = (byte)(input >>> 56);
        return output;
    }

    /**
     * convert an integer to a byte array of length 8.
     *
     * @param input  the integer to convert
     * @param output byte array holding the output
     * @param outoff offset in output array where the result is stored
     */
    public static void i2osp(long input, byte[] output, int outoff)
    {
        output[outoff++] = (byte)input;
        output[outoff++] = (byte)(input >>> 8);
        output[outoff++] = (byte)(input >>> 16);
        output[outoff++] = (byte)(input >>> 24);
        output[outoff++] = (byte)(input >>> 32);
        output[outoff++] = (byte)(input >>> 40);
        output[outoff++] = (byte)(input >>> 48);
        output[outoff] = (byte)(input >>> 56);
    }

    /**
     * convert an int array to a byte array of the specified length. no length
     * checking is performed (i.e., if the last integer cannot be encoded with
     * <tt>length % 4</tt> octets, it is truncated).
     *
     * @param input  the int array
     * @param outlen the length of the converted array
     * @return the converted array
     */
    public static byte[] tobytearray(int[] input, int outlen)
    {
        int intlen = input.length;
        byte[] result = new byte[outlen];
        int index = 0;
        for (int i = 0; i <= intlen - 2; i++, index += 4)
        {
            i2osp(input[i], result, index);
        }
        i2osp(input[intlen - 1], result, index, outlen - index);
        return result;
    }

    /**
     * convert a byte array to an int array.
     *
     * @param input the byte array
     * @return the converted array
     */
    public static int[] tointarray(byte[] input)
    {
        int intlen = (input.length + 3) / 4;
        int lastlen = input.length & 0x03;
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
