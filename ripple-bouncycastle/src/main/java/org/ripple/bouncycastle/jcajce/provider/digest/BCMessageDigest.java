package org.ripple.bouncycastle.jcajce.provider.digest;

import java.security.messagedigest;

import org.ripple.bouncycastle.crypto.digest;

public class bcmessagedigest
    extends messagedigest
{
    protected digest  digest;

    protected bcmessagedigest(
        digest digest)
    {
        super(digest.getalgorithmname());

        this.digest = digest;
    }

    public void enginereset() 
    {
        digest.reset();
    }

    public void engineupdate(
        byte    input) 
    {
        digest.update(input);
    }

    public void engineupdate(
        byte[]  input,
        int     offset,
        int     len) 
    {
        digest.update(input, offset, len);
    }

    public byte[] enginedigest() 
    {
        byte[]  digestbytes = new byte[digest.getdigestsize()];

        digest.dofinal(digestbytes, 0);

        return digestbytes;
    }
}
