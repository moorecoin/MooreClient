package org.ripple.bouncycastle.bcpg;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

/**
 * base class for a pgp object.
 */
public abstract class bcpgobject 
{
    public byte[] getencoded() 
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        bcpgoutputstream         pout = new bcpgoutputstream(bout);
        
        pout.writeobject(this);
        
        return bout.tobytearray();
    }
    
    public abstract void encode(bcpgoutputstream out)
        throws ioexception;
}
