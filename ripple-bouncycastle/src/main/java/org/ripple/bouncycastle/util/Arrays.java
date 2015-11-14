package org.ripple.bouncycastle.util;

import java.math.biginteger;

/**
 * general array utilities.
 */
public final class arrays
{
    private arrays() 
    {
        // static class, hide constructor
    }
    
    public static boolean areequal(
        boolean[]  a,
        boolean[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static boolean areequal(
        char[]  a,
        char[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static boolean areequal(
        byte[]  a,
        byte[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    /**
     * a constant time equals comparison - does not terminate early if
     * test will fail.
     *
     * @param a first array
     * @param b second array
     * @return true if arrays equal, false otherwise.
     */
    public static boolean constanttimeareequal(
        byte[]  a,
        byte[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        int nonequal = 0;

        for (int i = 0; i != a.length; i++)
        {
            nonequal |= (a[i] ^ b[i]);
        }

        return nonequal == 0;
    }

    public static boolean areequal(
        int[]  a,
        int[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static boolean areequal(
        long[]  a,
        long[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public static boolean areequal(
        biginteger[]  a,
        biginteger[]  b)
    {
        if (a == b)
        {
            return true;
        }

        if (a == null || b == null)
        {
            return false;
        }

        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (!a[i].equals(b[i]))
            {
                return false;
            }
        }

        return true;
    }

    public static void fill(
        byte[] array,
        byte value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        char[] array,
        char value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        long[] array,
        long value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        short[] array, 
        short value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }

    public static void fill(
        int[] array,
        int value)
    {
        for (int i = 0; i < array.length; i++)
        {
            array[i] = value;
        }
    }
    
    public static int hashcode(byte[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashcode(char[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashcode(int[][] ints)
    {
        int hc = 0;

        for (int i = 0; i != ints.length; i++)
        {
            hc = hc * 257 + hashcode(ints[i]);
        }

        return hc;
    }

    public static int hashcode(int[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[i];
        }

        return hc;
    }

    public static int hashcode(short[][][] shorts)
    {
        int hc = 0;

        for (int i = 0; i != shorts.length; i++)
        {
            hc = hc * 257 + hashcode(shorts[i]);
        }

        return hc;
    }

    public static int hashcode(short[][] shorts)
    {
        int hc = 0;

        for (int i = 0; i != shorts.length; i++)
        {
            hc = hc * 257 + hashcode(shorts[i]);
        }

        return hc;
    }

    public static int hashcode(short[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= (data[i] & 0xff);
        }

        return hc;
    }

    public static int hashcode(biginteger[] data)
    {
        if (data == null)
        {
            return 0;
        }

        int i = data.length;
        int hc = i + 1;

        while (--i >= 0)
        {
            hc *= 257;
            hc ^= data[i].hashcode();
        }

        return hc;
    }

    public static byte[] clone(byte[] data)
    {
        if (data == null)
        {
            return null;
        }
        byte[] copy = new byte[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static byte[][] clone(byte[][] data)
    {
        if (data == null)
        {
            return null;
        }

        byte[][] copy = new byte[data.length][];

        for (int i = 0; i != copy.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    public static byte[][][] clone(byte[][][] data)
    {
        if (data == null)
        {
            return null;
        }

        byte[][][] copy = new byte[data.length][][];

        for (int i = 0; i != copy.length; i++)
        {
            copy[i] = clone(data[i]);
        }

        return copy;
    }

    public static int[] clone(int[] data)
    {
        if (data == null)
        {
            return null;
        }
        int[] copy = new int[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static short[] clone(short[] data)
    {
        if (data == null)
        {
            return null;
        }
        short[] copy = new short[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static biginteger[] clone(biginteger[] data)
    {
        if (data == null)
        {
            return null;
        }
        biginteger[] copy = new biginteger[data.length];

        system.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

    public static byte[] copyof(byte[] data, int newlength)
    {
        byte[] tmp = new byte[newlength];

        if (newlength < data.length)
        {
            system.arraycopy(data, 0, tmp, 0, newlength);
        }
        else
        {
            system.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static char[] copyof(char[] data, int newlength)
    {
        char[] tmp = new char[newlength];

        if (newlength < data.length)
        {
            system.arraycopy(data, 0, tmp, 0, newlength);
        }
        else
        {
            system.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static int[] copyof(int[] data, int newlength)
    {
        int[] tmp = new int[newlength];

        if (newlength < data.length)
        {
            system.arraycopy(data, 0, tmp, 0, newlength);
        }
        else
        {
            system.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static long[] copyof(long[] data, int newlength)
    {
        long[] tmp = new long[newlength];

        if (newlength < data.length)
        {
            system.arraycopy(data, 0, tmp, 0, newlength);
        }
        else
        {
            system.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static biginteger[] copyof(biginteger[] data, int newlength)
    {
        biginteger[] tmp = new biginteger[newlength];

        if (newlength < data.length)
        {
            system.arraycopy(data, 0, tmp, 0, newlength);
        }
        else
        {
            system.arraycopy(data, 0, tmp, 0, data.length);
        }

        return tmp;
    }

    public static byte[] copyofrange(byte[] data, int from, int to)
    {
        int newlength = getlength(from, to);

        byte[] tmp = new byte[newlength];

        if (data.length - from < newlength)
        {
            system.arraycopy(data, from, tmp, 0, data.length - from);
        }
        else
        {
            system.arraycopy(data, from, tmp, 0, newlength);
        }

        return tmp;
    }

    public static int[] copyofrange(int[] data, int from, int to)
    {
        int newlength = getlength(from, to);

        int[] tmp = new int[newlength];

        if (data.length - from < newlength)
        {
            system.arraycopy(data, from, tmp, 0, data.length - from);
        }
        else
        {
            system.arraycopy(data, from, tmp, 0, newlength);
        }

        return tmp;
    }

    public static long[] copyofrange(long[] data, int from, int to)
    {
        int newlength = getlength(from, to);

        long[] tmp = new long[newlength];

        if (data.length - from < newlength)
        {
            system.arraycopy(data, from, tmp, 0, data.length - from);
        }
        else
        {
            system.arraycopy(data, from, tmp, 0, newlength);
        }

        return tmp;
    }

    public static biginteger[] copyofrange(biginteger[] data, int from, int to)
    {
        int newlength = getlength(from, to);

        biginteger[] tmp = new biginteger[newlength];

        if (data.length - from < newlength)
        {
            system.arraycopy(data, from, tmp, 0, data.length - from);
        }
        else
        {
            system.arraycopy(data, from, tmp, 0, newlength);
        }

        return tmp;
    }

    private static int getlength(int from, int to)
    {
        int newlength = to - from;
        if (newlength < 0)
        {
            stringbuffer sb = new stringbuffer(from);
            sb.append(" > ").append(to);
            throw new illegalargumentexception(sb.tostring());
        }
        return newlength;
    }

    public static byte[] concatenate(byte[] a, byte[] b)
    {
        if (a != null && b != null)
        {
            byte[] rv = new byte[a.length + b.length];

            system.arraycopy(a, 0, rv, 0, a.length);
            system.arraycopy(b, 0, rv, a.length, b.length);

            return rv;
        }
        else if (b != null)
        {
            return clone(b);
        }
        else
        {
            return clone(a);
        }
    }

    public static byte[] concatenate(byte[] a, byte[] b, byte[] c)
    {
        if (a != null && b != null && c != null)
        {
            byte[] rv = new byte[a.length + b.length + c.length];

            system.arraycopy(a, 0, rv, 0, a.length);
            system.arraycopy(b, 0, rv, a.length, b.length);
            system.arraycopy(c, 0, rv, a.length + b.length, c.length);

            return rv;
        }
        else if (b == null)
        {
            return concatenate(a, c);
        }
        else
        {
            return concatenate(a, b);
        }
    }

    public static byte[] concatenate(byte[] a, byte[] b, byte[] c, byte[] d)
    {
        if (a != null && b != null && c != null && d != null)
        {
            byte[] rv = new byte[a.length + b.length + c.length + d.length];

            system.arraycopy(a, 0, rv, 0, a.length);
            system.arraycopy(b, 0, rv, a.length, b.length);
            system.arraycopy(c, 0, rv, a.length + b.length, c.length);
            system.arraycopy(d, 0, rv, a.length + b.length + c.length, d.length);

            return rv;
        }
        else if (d == null)
        {
            return concatenate(a, b, c);
        }
        else if (c == null)
        {
            return concatenate(a, b, d);
        }
        else if (b == null)
        {
            return concatenate(a, c, d);
        }
        else
        {
            return concatenate(b, c, d);
        }
    }
}
