package org.ripple.bouncycastle.asn1;

import java.io.ioexception;
import java.io.inputstream;

class constructedoctetstream
    extends inputstream
{
    private final asn1streamparser _parser;

    private boolean                _first = true;
    private inputstream            _currentstream;

    constructedoctetstream(
        asn1streamparser parser)
    {
        _parser = parser;
    }

    public int read(byte[] b, int off, int len) throws ioexception
    {
        if (_currentstream == null)
        {
            if (!_first)
            {
                return -1;
            }

            asn1octetstringparser s = (asn1octetstringparser)_parser.readobject();

            if (s == null)
            {
                return -1;
            }

            _first = false;
            _currentstream = s.getoctetstream();
        }

        int totalread = 0;

        for (;;)
        {
            int numread = _currentstream.read(b, off + totalread, len - totalread);

            if (numread >= 0)
            {
                totalread += numread;

                if (totalread == len)
                {
                    return totalread;
                }
            }
            else
            {
                asn1octetstringparser aos = (asn1octetstringparser)_parser.readobject();

                if (aos == null)
                {
                    _currentstream = null;
                    return totalread < 1 ? -1 : totalread;
                }

                _currentstream = aos.getoctetstream();
            }
        }
    }

    public int read()
        throws ioexception
    {
        if (_currentstream == null)
        {
            if (!_first)
            {
                return -1;
            }

            asn1octetstringparser s = (asn1octetstringparser)_parser.readobject();
    
            if (s == null)
            {
                return -1;
            }
    
            _first = false;
            _currentstream = s.getoctetstream();
        }

        for (;;)
        {
            int b = _currentstream.read();

            if (b >= 0)
            {
                return b;
            }

            asn1octetstringparser s = (asn1octetstringparser)_parser.readobject();

            if (s == null)
            {
                _currentstream = null;
                return -1;
            }

            _currentstream = s.getoctetstream();
        }
    }
}
