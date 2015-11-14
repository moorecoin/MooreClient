package org.ripple.bouncycastle.bcpg;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

/**
 * basic type for a pgp packet.
 */
public abstract class containedpacket 
    extends packet
{
    public byte[] getencoded() 
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        bcpgoutputstream         pout = new bcpgoutputstream(bout);
        
        pout.writepacket(this);
        
        return bout.tobytearray();
    }
    
    public abstract void encode(
        bcpgoutputstream    pout)
        throws ioexception;
}
