package org.ripple.bouncycastle.crypto.io;

import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.signer;

public class signeroutputstream
    extends outputstream
{
    protected signer signer;

    public signeroutputstream(
        signer          signer)
    {
        this.signer = signer;
    }

    public void write(int b)
        throws ioexception
    {
        signer.update((byte)b);
    }

    public void write(
        byte[] b,
        int off,
        int len)
        throws ioexception
    {
        signer.update(b, off, len);
    }

    public signer getsigner()
    {
        return signer;
    }
}
