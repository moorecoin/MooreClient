package org.ripple.bouncycastle.asn1;

import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.util.io.streams;

class definitelengthinputstream
        extends limitedinputstream
{
    private static final byte[] empty_bytes = new byte[0];

    private final int _originallength;
    private int _remaining;

    definitelengthinputstream(
        inputstream in,
        int         length)
    {
        super(in, length);

        if (length < 0)
        {
            throw new illegalargumentexception("negative lengths not allowed");
        }

        this._originallength = length;
        this._remaining = length;

        if (length == 0)
        {
            setparenteofdetect(true);
        }
    }

    int getremaining()
    {
        return _remaining;
    }

    public int read()
        throws ioexception
    {
        if (_remaining == 0)
        {
            return -1;
        }

        int b = _in.read();

        if (b < 0)
        {
            throw new eofexception("def length " + _originallength + " object truncated by " + _remaining);
        }

        if (--_remaining == 0)
        {
            setparenteofdetect(true);
        }

        return b;
    }

    public int read(byte[] buf, int off, int len)
        throws ioexception
    {
        if (_remaining == 0)
        {
            return -1;
        }

        int toread = math.min(len, _remaining);
        int numread = _in.read(buf, off, toread);

        if (numread < 0)
        {
            throw new eofexception("def length " + _originallength + " object truncated by " + _remaining);
        }

        if ((_remaining -= numread) == 0)
        {
            setparenteofdetect(true);
        }

        return numread;
    }

    byte[] tobytearray()
        throws ioexception
    {
        if (_remaining == 0)
        {
            return empty_bytes;
        }

        byte[] bytes = new byte[_remaining];
        if ((_remaining -= streams.readfully(_in, bytes)) != 0)
        {
            throw new eofexception("def length " + _originallength + " object truncated by " + _remaining);
        }
        setparenteofdetect(true);
        return bytes;
    }
}
