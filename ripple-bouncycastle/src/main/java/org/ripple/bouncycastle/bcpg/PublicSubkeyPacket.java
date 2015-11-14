package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.util.date;

/**
 * basic packet for a pgp public key
 */
public class publicsubkeypacket 
    extends publickeypacket
{
    publicsubkeypacket(
        bcpginputstream    in)
        throws ioexception
    {      
        super(in);
    }
    
    /**
     * construct version 4 public key packet.
     * 
     * @param algorithm
     * @param time
     * @param key
     */
    public publicsubkeypacket(
        int       algorithm,
        date      time,
        bcpgkey   key)
    {
        super(algorithm, time, key);
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writepacket(public_subkey, getencodedcontents(), true);
    }
}
