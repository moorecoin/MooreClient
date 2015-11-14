package org.ripple.bouncycastle.bcpg;

/**
 *
 */
public class inputstreampacket
    extends packet
{
    private bcpginputstream        in;
    
    public inputstreampacket(
        bcpginputstream  in)
    {
        this.in = in;
    }
    
    /**
     * note: you can only read from this once...
     *
     * @return the inputstream
     */
    public bcpginputstream getinputstream()
    {
        return in;
    }
}
