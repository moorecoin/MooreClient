package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.math.biginteger;

/**
 * a multiple precision integer
 */
public class mpinteger 
    extends bcpgobject
{
    biginteger    value = null;
    
    public mpinteger(
        bcpginputstream    in)
        throws ioexception
    {
        int       length = (in.read() << 8) | in.read();
        byte[]    bytes = new byte[(length + 7) / 8];
        
        in.readfully(bytes);
        
        value = new biginteger(1, bytes);
    }
    
    public mpinteger(
        biginteger    value)
    {
        if (value == null || value.signum() < 0)
        {
            throw new illegalargumentexception("value must not be null, or negative");
        }

        this.value = value;
    }
    
    public biginteger getvalue()
    {
        return value;
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        int length = value.bitlength();
        
        out.write(length >> 8);
        out.write(length);
        
        byte[]    bytes = value.tobytearray();
        
        if (bytes[0] == 0)
        {
            out.write(bytes, 1, bytes.length - 1);
        }
        else
        {
            out.write(bytes, 0, bytes.length);
        }
    }
}
