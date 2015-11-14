package org.ripple.bouncycastle.crypto.io;

import java.io.filterinputstream;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.crypto.digest;

public class digestinputstream
    extends filterinputstream
{
    protected digest digest;

    public digestinputstream(
        inputstream stream,
        digest      digest)
    {
        super(stream);
        this.digest = digest;
    }

    public int read()
        throws ioexception
    {
        int b = in.read();

        if (b >= 0)
        {
            digest.update((byte)b);
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
            digest.update(b, off, n);
        }
        return n;
    }

    public digest getdigest()
    {
        return digest;
    }
}
