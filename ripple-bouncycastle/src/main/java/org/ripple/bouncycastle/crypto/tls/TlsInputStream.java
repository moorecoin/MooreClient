package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;

/**
 * an inputstream for an tls 1.0 connection.
 */
class tlsinputstream
    extends inputstream
{
    private byte[] buf = new byte[1];
    private tlsprotocol handler = null;

    tlsinputstream(tlsprotocol handler)
    {
        this.handler = handler;
    }

    public int read(byte[] buf, int offset, int len)
        throws ioexception
    {
        return this.handler.readapplicationdata(buf, offset, len);
    }

    public int read()
        throws ioexception
    {
        if (this.read(buf) < 0)
        {
            return -1;
        }
        return buf[0] & 0xff;
    }

    public void close()
        throws ioexception
    {
        handler.close();
    }
}
