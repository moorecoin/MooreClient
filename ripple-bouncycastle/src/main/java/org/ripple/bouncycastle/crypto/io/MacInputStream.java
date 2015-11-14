package org.ripple.bouncycastle.crypto.io;

import java.io.filterinputstream;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.crypto.mac;

public class macinputstream
    extends filterinputstream
{
    protected mac mac;

    public macinputstream(
        inputstream stream,
        mac         mac)
    {
        super(stream);
        this.mac = mac;
    }

    public int read()
        throws ioexception
    {
        int b = in.read();

        if (b >= 0)
        {
            mac.update((byte)b);
        }
        return b;
    }

    public int read(
        byte[] b,
        int off,
        int len)
        throws ioexception
    {
        int n = in.read(b, off, len);
        if (n >= 0)
        {
            mac.update(b, off, n);
        }
        return n;
    }

    public mac getmac()
    {
        return mac;
    }
}
