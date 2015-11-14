package org.ripple.bouncycastle.crypto.util;

public abstract class pack
{
    public static int bigendiantoint(byte[] bs, int off)
    {
        int n = bs[  off] << 24;
        n |= (bs[++off] & 0xff) << 16;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff);
        return n;
    }

    public static void bigendiantoint(byte[] bs, int off, int[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = bigendiantoint(bs, off);
            off += 4;
        }
    }

    public static byte[] inttobigendian(int n)
    {
        byte[] bs = new byte[4];
        inttobigendian(n, bs, 0);
        return bs;
    }

    public static void inttobigendian(int n, byte[] bs, int off)
    {
        bs[  off] = (byte)(n >>> 24);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n       );
    }

    public static byte[] inttobigendian(int[] ns)
    {
        byte[] bs = new byte[4 * ns.length];
        inttobigendian(ns, bs, 0);
        return bs;
    }

    public static void inttobigendian(int[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            inttobigendian(ns[i], bs, off);
            off += 4;
        }
    }

    public static long bigendiantolong(byte[] bs, int off)
    {
        int hi = bigendiantoint(bs, off);
        int lo = bigendiantoint(bs, off + 4);
        return ((long)(hi & 0xffffffffl) << 32) | (long)(lo & 0xffffffffl);
    }

    public static void bigendiantolong(byte[] bs, int off, long[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = bigendiantolong(bs, off);
            off += 8;
        }
    }

    public static byte[] longtobigendian(long n)
    {
        byte[] bs = new byte[8];
        longtobigendian(n, bs, 0);
        return bs;
    }

    public static void longtobigendian(long n, byte[] bs, int off)
    {
        inttobigendian((int)(n >>> 32), bs, off);
        inttobigendian((int)(n & 0xffffffffl), bs, off + 4);
    }

    public static byte[] longtobigendian(long[] ns)
    {
        byte[] bs = new byte[8 * ns.length];
        longtobigendian(ns, bs, 0);
        return bs;
    }

    public static void longtobigendian(long[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            longtobigendian(ns[i], bs, off);
            off += 8;
        }
    }

    public static int littleendiantoint(byte[] bs, int off)
    {
        int n = bs[  off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    public static void littleendiantoint(byte[] bs, int off, int[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleendiantoint(bs, off);
            off += 4;
        }
    }

    public static byte[] inttolittleendian(int n)
    {
        byte[] bs = new byte[4];
        inttolittleendian(n, bs, 0);
        return bs;
    }

    public static void inttolittleendian(int n, byte[] bs, int off)
    {
        bs[  off] = (byte)(n       );
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    public static byte[] inttolittleendian(int[] ns)
    {
        byte[] bs = new byte[4 * ns.length];
        inttolittleendian(ns, bs, 0);
        return bs;
    }

    public static void inttolittleendian(int[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            inttolittleendian(ns[i], bs, off);
            off += 4;
        }
    }

    public static long littleendiantolong(byte[] bs, int off)
    {
        int lo = littleendiantoint(bs, off);
        int hi = littleendiantoint(bs, off + 4);
        return ((long)(hi & 0xffffffffl) << 32) | (long)(lo & 0xffffffffl);
    }

    public static void littleendiantolong(byte[] bs, int off, long[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleendiantolong(bs, off);
            off += 8;
        }
    }

    public static byte[] longtolittleendian(long n)
    {
        byte[] bs = new byte[8];
        longtolittleendian(n, bs, 0);
        return bs;
    }

    public static void longtolittleendian(long n, byte[] bs, int off)
    {
        inttolittleendian((int)(n & 0xffffffffl), bs, off);
        inttolittleendian((int)(n >>> 32), bs, off + 4);
    }

    public static byte[] longtolittleendian(long[] ns)
    {
        byte[] bs = new byte[8 * ns.length];
        longtolittleendian(ns, bs, 0);
        return bs;
    }

    public static void longtolittleendian(long[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            longtolittleendian(ns[i], bs, off);
            off += 8;
        }
    }
}
