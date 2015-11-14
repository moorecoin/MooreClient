package org.ripple.bouncycastle.util.io;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

public class teeinputstream
    extends inputstream
{
    private final inputstream input;
    private final outputstream output;

    public teeinputstream(inputstream input, outputstream output)
    {
        this.input = input;
        this.output = output;
    }

    public int read(byte[] buf)
        throws ioexception
    {
        return read(buf, 0, buf.length);
    }

    public int read(byte[] buf, int off, int len)
        throws ioexception
    {
        int i = input.read(buf, off, len);

        if (i > 0)
        {
            output.write(buf, off, i);
        }

        return i;
    }

    public int read()
        throws ioexception
    {
        int i = input.read();

        if (i >= 0)
        {
            output.write(i);
        }

        return i;
    }

    public void close()
        throws ioexception
    {
        this.input.close();
        this.output.close();
    }

    public outputstream getoutputstream()
    {
        return output;
    }
}
