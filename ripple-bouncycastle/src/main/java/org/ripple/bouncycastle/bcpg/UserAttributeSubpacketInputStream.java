package org.ripple.bouncycastle.bcpg;

import java.io.*;

import org.ripple.bouncycastle.bcpg.attr.imageattribute;

/**
 * reader for user attribute sub-packets
 */
public class userattributesubpacketinputstream
    extends inputstream implements userattributesubpackettags
{
    inputstream    in;
    
    public userattributesubpacketinputstream(
        inputstream    in)
    {
        this.in = in;
    }
    
    public int available()
        throws ioexception
    {
        return in.available();
    }
    
    public int read()
        throws ioexception
    {
        return in.read();
    }
    
    private void readfully(
        byte[]    buf,
        int       off,
        int       len)
        throws ioexception
    {
        if (len > 0)
        {
            int    b = this.read();
            
            if (b < 0)
            {
                throw new eofexception();
            }
            
            buf[off] = (byte)b;
            off++;
            len--;
        }
        
        while (len > 0)
        {
            int    l = in.read(buf, off, len);
            
            if (l < 0)
            {
                throw new eofexception();
            }
            
            off += l;
            len -= l;
        }
    }
    
    public userattributesubpacket readpacket()
        throws ioexception
    {
        int            l = this.read();
        int            bodylen = 0;
        
        if (l < 0)
        {
            return null;
        }

        if (l < 192)
        {
            bodylen = l;
        }
        else if (l <= 223)
        {
            bodylen = ((l - 192) << 8) + (in.read()) + 192;
        }
        else if (l == 255)
        {
            bodylen = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
        }
        else
        {
            // todo error?
        }

       int        tag = in.read();

       if (tag < 0)
       {
               throw new eofexception("unexpected eof reading user attribute sub packet");
       }
       
       byte[]    data = new byte[bodylen - 1];

       this.readfully(data, 0, data.length);
       
       int       type = tag;

       switch (type)
       {
       case image_attribute:
           return new imageattribute(data);
       }

       return new userattributesubpacket(type, data);
    }
}
