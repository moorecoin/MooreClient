package org.ripple.bouncycastle.openpgp.operator.bc;

import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.signer;

class signeroutputstream
    extends outputstream
{
    private signer sig;

    signeroutputstream(signer sig)
    {
        this.sig = sig;
    }

    public void write(byte[] bytes, int off, int len)
        throws ioexception
    {
        sig.update(bytes, off, len);
    }

    public void write(byte[] bytes)
        throws ioexception
    {
        sig.update(bytes, 0, bytes.length);
    }

    public void write(int b)
        throws ioexception
    {
        sig.update((byte)b);
    }
}
