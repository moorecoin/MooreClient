package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;
import java.io.outputstream;

/**
 * basic type for a pgp signature sub-packet.
 */
public class signaturesubpacket 
{
    int               type;
    boolean           critical;
    
    protected byte[]  data;
    
    protected signaturesubpacket(
        int           type,
        boolean       critical,
        byte[]        data)
    {    
        this.type = type;
        this.critical = critical;
        this.data = data;
    }
    
    public int gettype()
    {
        return type;
    }
    
    public boolean iscritical()
    {
        return critical;
    }
    
    /**
     * return the generic data making up the packet.
     */
    public byte[] getdata()
    {
        return data;
    }

    public void encode(
        outputstream    out)
        throws ioexception
    {
        int    bodylen = data.length + 1;
        
        if (bodylen < 192)
        {
            out.write((byte)bodylen);
        }
        else if (bodylen <= 8383)
        {
            bodylen -= 192;
            
            out.write((byte)(((bodylen >> 8) & 0xff) + 192));
            out.write((byte)bodylen);
        }
        else
        {
            out.write(0xff);
            out.write((byte)(bodylen >> 24));
            out.write((byte)(bodylen >> 16));
            out.write((byte)(bodylen >> 8));
            out.write((byte)bodylen);
        }
        
        if (critical)
        {
            out.write(0x80 | type);
        }
        else
        {
            out.write(type);
        }
        
        out.write(data);
    }
}
