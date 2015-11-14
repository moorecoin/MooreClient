package org.ripple.bouncycastle.asn1;

import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;

class indefinitelengthinputstream
    extends limitedinputstream
{
    private int _b1;
    private int _b2;
    private boolean _eofreached = false;
    private boolean _eofon00 = true;

    indefinitelengthinputstream(
        inputstream in,
        int         limit)
        throws ioexception
    {
        super(in, limit);

        _b1 = in.read();
        _b2 = in.read();

        if (_b2 < 0)
        {
            // corrupted stream
            throw new eofexception();
        }

        checkforeof();
    }

    void seteofon00(
        boolean eofon00)
    {
        _eofon00 = eofon00;
        checkforeof();
    }

    private boolean checkforeof()
    {
        if (!_eofreached && _eofon00 && (_b1 == 0x00 && _b2 == 0x00))
        {
            _eofreached = true;
            setparenteofdetect(true);
        }
        return _eofreached;
    }

    public int read(byte[] b, int off, int len)
        throws ioexception
    {
        // only use this optimisation if we aren't checking for 00
        if (_eofon00 || len < 3)
        {
            return super.read(b, off, len);
        }

        if (_eofreached)
        {
            return -1;
        }

        int numread = _in.read(b, off + 2, len - 2);

        if (numread < 0)
        {
            // corrupted stream
            throw new eofexception();
        }

        b[off] = (byte)_b1;
        b[off + 1] = (byte)_b2;

        _b1 = _in.read();
        _b2 = _in.read();

        if (_b2 < 0)
        {
            // corrupted stream
            throw new eofexception();
        }

        return numread + 2;
    }

    public int read()
        throws ioexception
    {
        if (checkforeof())
        {
            return -1;
        }

        int b = _in.read();

        if (b < 0)
        {
            // corrupted stream
            throw new eofexception();
        }

        int v = _b1;

        _b1 = _b2;
        _b2 = b;

        return v;
    }
}
