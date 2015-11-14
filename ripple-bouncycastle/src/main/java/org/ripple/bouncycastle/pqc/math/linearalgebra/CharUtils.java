package org.ripple.bouncycastle.pqc.math.linearalgebra;

public final class charutils
{

    /**
     * default constructor (private)
     */
    private charutils()
    {
        // empty
    }

    /**
     * return a clone of the given char array. no null checks are performed.
     *
     * @param array the array to clone
     * @return the clone of the given array
     */
    public static char[] clone(char[] array)
    {
        char[] result = new char[array.length];
        system.arraycopy(array, 0, result, 0, array.length);
        return result;
    }

    /**
     * convert the given char array into a byte array.
     *
     * @param chars the char array
     * @return the converted array
     */
    public static byte[] tobytearray(char[] chars)
    {
        byte[] result = new byte[chars.length];
        for (int i = chars.length - 1; i >= 0; i--)
        {
            result[i] = (byte)chars[i];
        }
        return result;
    }

    /**
     * convert the given char array into a
     * byte array for use with pbe encryption.
     *
     * @param chars the char array
     * @return the converted array
     */
    public static byte[] tobytearrayforpbe(char[] chars)
    {

        byte[] out = new byte[chars.length];

        for (int i = 0; i < chars.length; i++)
        {
            out[i] = (byte)chars[i];
        }

        int length = out.length * 2;
        byte[] ret = new byte[length + 2];

        int j = 0;
        for (int i = 0; i < out.length; i++)
        {
            j = i * 2;
            ret[j] = 0;
            ret[j + 1] = out[i];
        }

        ret[length] = 0;
        ret[length + 1] = 0;

        return ret;
    }

    /**
     * compare two char arrays. no null checks are performed.
     *
     * @param left  the char byte array
     * @param right the second char array
     * @return the result of the comparison
     */
    public static boolean equals(char[] left, char[] right)
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

}
