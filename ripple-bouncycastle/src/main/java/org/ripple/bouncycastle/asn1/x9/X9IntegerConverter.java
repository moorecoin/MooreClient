package org.ripple.bouncycastle.asn1.x9;

import java.math.biginteger;

import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecfieldelement;

public class x9integerconverter
{
    public int getbytelength(
        eccurve c)
    {
        return (c.getfieldsize() + 7) / 8;
    }

    public int getbytelength(
        ecfieldelement fe)
    {
        return (fe.getfieldsize() + 7) / 8;
    }

    public byte[] integertobytes(
        biginteger s,
        int        qlength)
    {
        byte[] bytes = s.tobytearray();
        
        if (qlength < bytes.length)
        {
            byte[] tmp = new byte[qlength];
        
            system.arraycopy(bytes, bytes.length - tmp.length, tmp, 0, tmp.length);
            
            return tmp;
        }
        else if (qlength > bytes.length)
        {
            byte[] tmp = new byte[qlength];
        
            system.arraycopy(bytes, 0, tmp, tmp.length - bytes.length, bytes.length);
            
            return tmp; 
        }
    
        return bytes;
    }
}
