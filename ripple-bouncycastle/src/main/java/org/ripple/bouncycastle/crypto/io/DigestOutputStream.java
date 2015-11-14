package org.ripple.bouncycastle.crypto.io;

import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.digest;

public class digestoutputstream
    extends outputstream
{
    protected digest digest;

    public digestoutputstream(
        digest          digest)
    {
        this.digest = digest;
    }

    public void write(int b)
        throws ioexception
    {
        digest.update((byte)b);
    }

    public void write(
        byte[] b,
        int off,
        int len)
        throws ioexception
    {
        digest.update(b, off, len);
    }

    public byte[] getdigest()
    {
        byte[] res = new byte[digest.getdigestsize()];
        
        digest.dofinal(res, 0);
        
        return res;
    }
}
