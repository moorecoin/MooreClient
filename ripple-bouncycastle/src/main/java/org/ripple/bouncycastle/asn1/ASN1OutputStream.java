package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.outputstream;

/**
 * stream that produces output based on the default encoding for the passed in objects.
 */
public class asn1outputstream
{
    private outputstream os;

    public asn1outputstream(
        outputstream    os)
    {
        this.os = os;
    }

    void writelength(
        int length)
        throws ioexception
    {
        if (length > 127)
        {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0)
            {
                size++;
            }

            write((byte)(size | 0x80));

            for (int i = (size - 1) * 8; i >= 0; i -= 8)
            {
                write((byte)(length >> i));
            }
        }
        else
        {
            write((byte)length);
        }
    }

    void write(int b)
        throws ioexception
    {
        os.write(b);
    }

    void write(byte[] bytes)
        throws ioexception
    {
        os.write(bytes);
    }

    void write(byte[] bytes, int off, int len)
        throws ioexception
    {
        os.write(bytes, off, len);
    }

    void writeencoded(
        int     tag,
        byte[]  bytes)
        throws ioexception
    {
        write(tag);
        writelength(bytes.length);
        write(bytes);
    }

    void writetag(int flags, int tagno)
        throws ioexception
    {
        if (tagno < 31)
        {
            write(flags | tagno);
        }
        else
        {
            write(flags | 0x1f);
            if (tagno < 128)
            {
                write(tagno);
            }
            else
            {
                byte[] stack = new byte[5];
                int pos = stack.length;

                stack[--pos] = (byte)(tagno & 0x7f);

                do
                {
                    tagno >>= 7;
                    stack[--pos] = (byte)(tagno & 0x7f | 0x80);
                }
                while (tagno > 127);

                write(stack, pos, stack.length - pos);
            }
        }
    }

    void writeencoded(int flags, int tagno, byte[] bytes)
        throws ioexception
    {
        writetag(flags, tagno);
        writelength(bytes.length);
        write(bytes);
    }

    protected void writenull()
        throws ioexception
    {
        os.write(bertags.null);
        os.write(0x00);
    }

    public void writeobject(
        asn1encodable obj)
        throws ioexception
    {
        if (obj != null)
        {
            obj.toasn1primitive().encode(this);
        }
        else
        {
            throw new ioexception("null object detected");
        }
    }

    void writeimplicitobject(asn1primitive obj)
        throws ioexception
    {
        if (obj != null)
        {
            obj.encode(new implicitoutputstream(os));
        }
        else
        {
            throw new ioexception("null object detected");
        }
    }

    public void close()
        throws ioexception
    {
        os.close();
    }

    public void flush()
        throws ioexception
    {
        os.flush();
    }

    asn1outputstream getdersubstream()
    {
        return new deroutputstream(os);
    }

    asn1outputstream getdlsubstream()
    {
        return new dloutputstream(os);
    }

    private class implicitoutputstream
        extends asn1outputstream
    {
        private boolean first = true;

        public implicitoutputstream(outputstream os)
        {
            super(os);
        }

        public void write(int b)
            throws ioexception
        {
            if (first)
            {
                first = false;
            }
            else
            {
                super.write(b);
            }
        }
    }
}
