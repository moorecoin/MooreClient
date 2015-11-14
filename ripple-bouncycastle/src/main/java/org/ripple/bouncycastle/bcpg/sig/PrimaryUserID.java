package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet giving whether or not the signature is signed using the primary user id for the key.
 */
public class primaryuserid 
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
    
    public primaryuserid(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.primary_user_id, critical, data);
    }
    
    public primaryuserid(
        boolean    critical,
        boolean    isprimaryuserid)
    {
        super(signaturesubpackettags.primary_user_id, critical, booleantobytearray(isprimaryuserid));
    }
    
    public boolean isprimaryuserid()
    {
        return data[0] != 0;
    }
}
