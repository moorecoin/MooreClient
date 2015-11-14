package org.ripple.bouncycastle.pqc.crypto.gmss.util;

/**
 * this class provides several methods that are required by the gmss classes.
 */
public class gmssutil
{
    /**
     * converts a 32 bit integer into a byte array beginning at
     * <code>offset</code> (little-endian representation)
     *
     * @param value the integer to convert
     */
    public byte[] inttobyteslittleendian(int value)
    {
        byte[] bytes = new byte[4];

        bytes[0] = (byte)((value) & 0xff);
        bytes[1] = (byte)((value >> 8) & 0xff);
        bytes[2] = (byte)((value >> 16) & 0xff);
        bytes[3] = (byte)((value >> 24) & 0xff);
        return bytes;
    }

    /**
     * converts a byte array beginning at <code>offset</code> into a 32 bit
     * integer (little-endian representation)
     *
     * @param bytes the byte array
     * @return the resulting integer
     */
    public int bytestointlittleendian(byte[] bytes)
    {

        return ((bytes[0] & 0xff)) | ((bytes[1] & 0xff) << 8)
            | ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff)) << 24;
    }

    /**
     * converts a byte array beginning at <code>offset</code> into a 32 bit
     * integer (little-endian representation)
     *
     * @param bytes  the byte array
     * @param offset the integer offset into the byte array
     * @return the resulting integer
     */
    public int bytestointlittleendian(byte[] bytes, int offset)
    {
        return ((bytes[offset++] & 0xff)) | ((bytes[offset++] & 0xff) << 8)
            | ((bytes[offset++] & 0xff) << 16)
            | ((bytes[offset] & 0xff)) << 24;
    }

    /**
     * this method concatenates a 2-dimensional byte array into a 1-dimensional
     * byte array
     *
     * @param arraycp a 2-dimensional byte array.
     * @return 1-dimensional byte array with concatenated input array
     */
    public byte[] concatenatearray(byte[][] arraycp)
    {
        byte[] dest = new byte[arraycp.length * arraycp[0].length];
        int indx = 0;
        for (int i = 0; i < arraycp.length; i++)
        {
            system.arraycopy(arraycp[i], 0, dest, indx, arraycp[i].length);
            indx = indx + arraycp[i].length;
        }
        return dest;
    }

    /**
     * this method prints the values of a 2-dimensional byte array
     *
     * @param text  a string
     * @param array a 2-dimensional byte array
     */
    public void printarray(string text, byte[][] array)
    {
        system.out.println(text);
        int counter = 0;
        for (int i = 0; i < array.length; i++)
        {
            for (int j = 0; j < array[0].length; j++)
            {
                system.out.println(counter + "; " + array[i][j]);
                counter++;
            }
        }
    }

    /**
     * this method prints the values of a 1-dimensional byte array
     *
     * @param text  a string
     * @param array a 1-dimensional byte array.
     */
    public void printarray(string text, byte[] array)
    {
        system.out.println(text);
        int counter = 0;
        for (int i = 0; i < array.length; i++)
        {
            system.out.println(counter + "; " + array[i]);
            counter++;
        }
    }

    /**
     * this method tests if an integer is a power of 2.
     *
     * @param testvalue an integer
     * @return <code>true</code> if <code>testvalue</code> is a power of 2,
     *         <code>false</code> otherwise
     */
    public boolean testpoweroftwo(int testvalue)
    {
        int a = 1;
        while (a < testvalue)
        {
            a <<= 1;
        }
        if (testvalue == a)
        {
            return true;
        }

        return false;
    }

    /**
     * this method returns the least integer that is greater or equal to the
     * logarithm to the base 2 of an integer <code>intvalue</code>.
     *
     * @param intvalue an integer
     * @return the least integer greater or equal to the logarithm to the base 2
     *         of <code>intvalue</code>
     */
    public int getlog(int intvalue)
    {
        int log = 1;
        int i = 2;
        while (i < intvalue)
        {
            i <<= 1;
            log++;
        }
        return log;
    }
}
