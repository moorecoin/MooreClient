package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.outputstream;

/**
 * an outputstream for an tls connection.
 */
class tlsoutputstream
    extends outputstream
{
    private byte[] buf = new byte[1];
    private tlsprotocol handler;

    tlsoutputstream(tlsprotocol handler)
    {
        this.handler = handler;
    }

    public void write(byte buf[], int offset, int len)
        throws ioexception
    {
        this.handler.writedata(buf, offset, len);
    }

    public void write(int arg0)
        throws ioexception
    {
        buf[0] = (byte)arg0;
        this.write(buf, 0, 1);
    }

    public void close()
        throws ioexception
    {
        handler.close();
    }

    public void flush()
        throws ioexception
    {
        handler.flush();
    }
}
