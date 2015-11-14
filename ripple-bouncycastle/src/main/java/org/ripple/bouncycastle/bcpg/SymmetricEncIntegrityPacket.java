package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;

/**
 */
public class symmetricencintegritypacket 
    extends inputstreampacket
{    
    int        version;
    
    symmetricencintegritypacket(
        bcpginputstream    in)
        throws ioexception
    {
        super(in);
        
        version = in.read();
    }
}
