package org.ripple.bouncycastle.bcpg;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

/**
 * basic type for a trust packet
 */
public class trustpacket 
    extends containedpacket
{    
    byte[]    levelandtrustamount;
    
    public trustpacket(
        bcpginputstream  in)
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        int                      ch;
        
        while ((ch = in.read()) >= 0)
        {
            bout.write(ch);
        }
        
        levelandtrustamount = bout.tobytearray();
    }
    
    public trustpacket(
        int    trustcode)
    {
        this.levelandtrustamount = new byte[1];
        
        this.levelandtrustamount[0] = (byte)trustcode;
    }

    public byte[] getlevelandtrustamount()
    {
        return levelandtrustamount;
    }

    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writepacket(trust, levelandtrustamount, true);
    }
}
