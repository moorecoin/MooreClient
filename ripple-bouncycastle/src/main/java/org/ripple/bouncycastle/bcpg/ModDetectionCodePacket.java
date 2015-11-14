package org.ripple.bouncycastle.bcpg;

import java.io.*;

/**
 * basic packet for a modification detection code packet.
 */
public class moddetectioncodepacket 
    extends containedpacket
{    
    private byte[]    digest;
    
    moddetectioncodepacket(
        bcpginputstream in)
        throws ioexception
    {    
        this.digest = new byte[20];
        in.readfully(this.digest);
    }
    
    public moddetectioncodepacket(
        byte[]    digest)
        throws ioexception
    {    
        this.digest = new byte[digest.length];
        
        system.arraycopy(digest, 0, this.digest, 0, this.digest.length);
    }
    
    public byte[] getdigest()
    {
        byte[] tmp = new byte[digest.length];
        
        system.arraycopy(digest, 0, tmp, 0, tmp.length);
        
        return tmp;
    }
    
    public void encode(
        bcpgoutputstream    out) 
        throws ioexception
    {
        out.writepacket(mod_detection_code, digest, false);
    }
}
