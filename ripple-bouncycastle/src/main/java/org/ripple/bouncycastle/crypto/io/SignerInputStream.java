package org.ripple.bouncycastle.crypto.io;

import java.io.filterinputstream;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.crypto.signer;

public class signerinputstream
    extends filterinputstream
{
    protected signer signer;

    public signerinputstream(
        inputstream stream,
        signer      signer)
    {
        super(stream);
        this.signer = signer;
    }

    public int read()
        throws ioexception
    {
        int b = in.read();

        if (b >= 0)
        {
            signer.update((byte)b);
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
        if (n > 0)
        {
            signer.update(b, off, n);
        }
        return n;
    }

    public signer getsigner()
    {
        return signer;
    }
}
