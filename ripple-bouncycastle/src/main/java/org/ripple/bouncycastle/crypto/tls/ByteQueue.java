package org.ripple.bouncycastle.crypto.tls;

/**
 * a queue for bytes. this file could be more optimized.
 */
public class bytequeue
{
    /**
     * @return the smallest number which can be written as 2^x which is bigger than i.
     */
    public static final int nexttwopow(int i)
    {
        /*
         * this code is based of a lot of code i found on the internet which mostly
         * referenced a book called "hacking delight".
         */
        i |= (i >> 1);
        i |= (i >> 2);
        i |= (i >> 4);
        i |= (i >> 8);
        i |= (i >> 16);
        return i + 1;
    }

    /**
     * the initial size for our buffer.
     */
    private static final int initbufsize = 1024;

    /**
     * the buffer where we store our data.
     */
    private byte[] databuf = new byte[bytequeue.initbufsize];

    /**
     * how many bytes at the beginning of the buffer are skipped.
     */
    private int skipped = 0;

    /**
     * how many bytes in the buffer are valid data.
     */
    private int available = 0;

    /**
     * read data from the buffer.
     *
     * @param buf    the buffer where the read data will be copied to.
     * @param offset how many bytes to skip at the beginning of buf.
     * @param len    how many bytes to read at all.
     * @param skip   how many bytes from our data to skip.
     */
    public void read(byte[] buf, int offset, int len, int skip)
    {
        if ((available - skip) < len)
        {
            throw new tlsruntimeexception("not enough data to read");
        }
        if ((buf.length - offset) < len)
        {
            throw new tlsruntimeexception("buffer size of " + buf.length
                + " is too small for a read of " + len + " bytes");
        }
        system.arraycopy(databuf, skipped + skip, buf, offset, len);
        return;
    }

    /**
     * add some data to our buffer.
     *
     * @param data   a byte-array to read data from.
     * @param offset how many bytes to skip at the beginning of the array.
     * @param len    how many bytes to read from the array.
     */
    public void adddata(byte[] data, int offset, int len)
    {
        if ((skipped + available + len) > databuf.length)
        {
            byte[] tmp = new byte[bytequeue.nexttwopow(data.length)];
            system.arraycopy(databuf, skipped, tmp, 0, available);
            skipped = 0;
            databuf = tmp;
        }
        system.arraycopy(data, offset, databuf, skipped + available, len);
        available += len;
    }

    /**
     * remove some bytes from our data from the beginning.
     *
     * @param i how many bytes to remove.
     */
    public void removedata(int i)
    {
        if (i > available)
        {
            throw new tlsruntimeexception("cannot remove " + i + " bytes, only got " + available);
        }

        /*
         * skip the data.
         */
        available -= i;
        skipped += i;

        /*
         * if more than half of our data is skipped, we will move the data in the buffer.
         */
        if (skipped > (databuf.length / 2))
        {
            system.arraycopy(databuf, skipped, databuf, 0, available);
            skipped = 0;
        }
    }

    /**
     * @return the number of bytes which are available in this buffer.
     */
    public int size()
    {
        return available;
    }
}
