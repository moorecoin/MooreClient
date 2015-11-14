package org.ripple.bouncycastle.util.io;

import java.io.ioexception;
import java.io.outputstream;

public class teeoutputstream
    extends outputstream
{
    private outputstream output1;
    private outputstream output2;

    public teeoutputstream(outputstream output1, outputstream output2)
    {
        this.output1 = output1;
        this.output2 = output2;
    }

    public void write(byte[] buf)
        throws ioexception
    {
        this.output1.write(buf);
        this.output2.write(buf);
    }

    public void write(byte[] buf, int off, int len)
        throws ioexception
    {
        this.output1.write(buf, off, len);
        this.output2.write(buf, off, len);
    }

    public void write(int b)
        throws ioexception
    {
        this.output1.write(b);
        this.output2.write(b);
    }

    public void flush()
        throws ioexception
    {
        this.output1.flush();
        this.output2.flush();
    }

    public void close()
        throws ioexception
    {
        this.output1.close();
        this.output2.close();
    }
}