package org.ripple.bouncycastle.crypto.io;

import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.mac;

public class macoutputstream
    extends outputstream
{
    protected mac mac;

    public macoutputstream(
        mac          mac)
    {
        this.mac = mac;
    }

    public void write(int b)
        throws ioexception
    {
        mac.update((byte)b);
    }

    public void write(
        byte[] b,
        int off,
        int len)
        throws ioexception
    {
        mac.update(b, off, len);
    }

    public byte[] getmac()
    {
        byte[] res = new byte[mac.getmacsize()];

        mac.dofinal(res, 0);

        return res;
    }
}
