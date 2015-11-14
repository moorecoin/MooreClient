package org.ripple.bouncycastle.util.io;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

public final class streams
{
    private static int buffer_size = 512;

    public static void drain(inputstream instr)
        throws ioexception
    {
        byte[] bs = new byte[buffer_size];
        while (instr.read(bs, 0, bs.length) >= 0)
        {
        }
    }

    public static byte[] readall(inputstream instr)
        throws ioexception
    {
        bytearrayoutputstream buf = new bytearrayoutputstream();
        pipeall(instr, buf);
        return buf.tobytearray();
    }

    public static byte[] readalllimited(inputstream instr, int limit)
        throws ioexception
    {
        bytearrayoutputstream buf = new bytearrayoutputstream();
        pipealllimited(instr, limit, buf);
        return buf.tobytearray();
    }

    public static int readfully(inputstream instr, byte[] buf)
        throws ioexception
    {
        return readfully(instr, buf, 0, buf.length);
    }

    public static int readfully(inputstream instr, byte[] buf, int off, int len)
        throws ioexception
    {
        int totalread = 0;
        while (totalread < len)
        {
            int numread = instr.read(buf, off + totalread, len - totalread);
            if (numread < 0)
            {
                break;
            }
            totalread += numread;
        }
        return totalread;
    }

    public static void pipeall(inputstream instr, outputstream outstr)
        throws ioexception
    {
        byte[] bs = new byte[buffer_size];
        int numread;
        while ((numread = instr.read(bs, 0, bs.length)) >= 0)
        {
            outstr.write(bs, 0, numread);
        }
    }

    public static long pipealllimited(inputstream instr, long limit, outputstream outstr)
        throws ioexception
    {
        long total = 0;
        byte[] bs = new byte[buffer_size];
        int numread;
        while ((numread = instr.read(bs, 0, bs.length)) >= 0)
        {
            total += numread;
            if (total > limit)
            {
                throw new streamoverflowexception("data overflow");
            }
            outstr.write(bs, 0, numread);
        }
        return total;
    }
}
