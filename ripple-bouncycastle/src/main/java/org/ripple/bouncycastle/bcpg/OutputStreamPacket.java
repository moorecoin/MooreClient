package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;

public abstract class outputstreampacket
{
    protected bcpgoutputstream    out;
    
    public outputstreampacket(
        bcpgoutputstream    out)
    {
        this.out = out;
    }
    
    public abstract bcpgoutputstream open() throws ioexception;
    
    public abstract void close() throws ioexception;
}
