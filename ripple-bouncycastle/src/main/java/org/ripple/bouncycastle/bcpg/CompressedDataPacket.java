package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;

/**
 * generic compressed data object.
 */
public class compresseddatapacket 
    extends inputstreampacket
{
    int    algorithm;
    
    compresseddatapacket(
        bcpginputstream    in)
        throws ioexception
    {
        super(in);
        
        algorithm = in.read();    
    }
    
    /**
     * return the algorithm tag value.
     * 
     * @return algorithm tag value.
     */
    public int getalgorithm()
    {
        return algorithm;
    }
}
