package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet giving signature creation time.
 */
public class exportable 
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
    
    public exportable(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.exportable, critical, data);
    }
    
    public exportable(
        boolean    critical,
        boolean    isexportable)
    {
        super(signaturesubpackettags.exportable, critical, booleantobytearray(isexportable));
    }
    
    public boolean isexportable()
    {
        return data[0] != 0;
    }
}
