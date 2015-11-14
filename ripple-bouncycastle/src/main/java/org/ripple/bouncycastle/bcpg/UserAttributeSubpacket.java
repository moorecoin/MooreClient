package org.ripple.bouncycastle.bcpg;

import org.ripple.bouncycastle.util.arrays;

import java.io.ioexception;
import java.io.outputstream;

/**
 * basic type for a user attribute sub-packet.
 */
public class userattributesubpacket 
{
    int                type;
    
    protected byte[]   data;
    
    protected userattributesubpacket(
        int            type,
        byte[]         data)
    {    
        this.type = type;
        this.data = data;
    }
    
    public int gettype()
    {
        return type;
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

        out.write(type);        
        out.write(data);
    }

    public boolean equals(
        object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof userattributesubpacket))
        {
            return false;
        }

        userattributesubpacket other = (userattributesubpacket)o;

        return this.type == other.type
            && arrays.areequal(this.data, other.data);
    }

    public int hashcode()
    {
        return type ^ arrays.hashcode(data);
    }
}
