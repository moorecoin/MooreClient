package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet giving whether or not is revocable.
 */
public class revocable 
    extends signaturesubpacket
{    
    private static byte[] booleantobytearray(
        boolean    value)
    {
        byte[]    data = new byte[1];
        
        if (value)
        {
            data[0] = 1;
            return data;
        }
        else
        {
            return data;
        }
    }
    
    public revocable(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.revocable, critical, data);
    }
    
    public revocable(
        boolean    critical,
        boolean    isrevocable)
    {
        super(signaturesubpackettags.revocable, critical, booleantobytearray(isrevocable));
    }
    
    public boolean isrevocable()
    {
        return data[0] != 0;
    }
}
