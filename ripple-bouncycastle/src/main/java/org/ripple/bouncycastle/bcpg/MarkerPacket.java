package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;

/**
 * basic type for a marker packet
 */
public class markerpacket 
    extends containedpacket
{    
    // "pgp"
        
    byte[]    marker = { (byte)0x50, (byte)0x47, (byte)0x50 };
    
    public markerpacket(
        bcpginputstream  in)
        throws ioexception
    {
         in.readfully(marker);
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writepacket(marker, marker, true);
    }
}
