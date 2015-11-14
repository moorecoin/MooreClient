package org.ripple.bouncycastle.openpgp;

import java.io.ioexception;
import java.io.outputstream;

class wrappedgeneratorstream
    extends outputstream
{
    private final outputstream    _out;
    private final streamgenerator _sgen;

    public wrappedgeneratorstream(outputstream out, streamgenerator sgen)
    {
        _out = out;
        _sgen = sgen;
    }
    public void write(byte[] bytes)
        throws ioexception
    {
        _out.write(bytes);
    }

    public void write(byte[] bytes, int offset, int length)
        throws ioexception
    {
        _out.write(bytes, offset, length);
    }

    public void write(int b)
        throws ioexception
    {
        _out.write(b);
    }

    public void flush()
        throws ioexception
    {
        _out.flush();
    }

    public void close()
        throws ioexception
    {
        _sgen.close();
    }
}
