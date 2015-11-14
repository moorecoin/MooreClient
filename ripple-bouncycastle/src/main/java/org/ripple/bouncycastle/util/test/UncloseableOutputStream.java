package org.ripple.bouncycastle.util.test;

import java.io.filteroutputstream;
import java.io.ioexception;
import java.io.outputstream;

public class uncloseableoutputstream extends filteroutputstream
{
    public uncloseableoutputstream(outputstream s)
    {
        super(s);
    }

    public void close()
    {
        throw new runtimeexception("close() called on uncloseableoutputstream");
    }

    public void write(byte[] b, int off, int len) throws ioexception
    {
        out.write(b, off, len);
    }
 }
