package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.io.ioexception;
import java.io.outputstream;
import java.security.signature;
import java.security.signatureexception;

class signatureoutputstream
    extends outputstream
{
    private signature sig;

    signatureoutputstream(signature sig)
    {
        this.sig = sig;
    }

    public void write(byte[] bytes, int off, int len)
        throws ioexception
    {
        try
        {
            sig.update(bytes, off, len);
        }
        catch (signatureexception e)
        {
            throw new ioexception("signature update caused exception: " + e.getmessage());
        }
    }

    public void write(byte[] bytes)
        throws ioexception
    {
        try
        {
            sig.update(bytes);
        }
        catch (signatureexception e)
        {
            throw new ioexception("signature update caused exception: " + e.getmessage());
        }
    }

    public void write(int b)
        throws ioexception
    {
        try
        {
            sig.update((byte)b);
        }
        catch (signatureexception e)
        {
            throw new ioexception("signature update caused exception: " + e.getmessage());
        }
    }
}
