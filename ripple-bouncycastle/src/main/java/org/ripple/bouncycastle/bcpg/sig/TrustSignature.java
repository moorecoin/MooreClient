package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet giving trust.
 */
public class trustsignature 
    extends signaturesubpacket
{    
    private static byte[] inttobytearray(
        int    v1,
        int    v2)
    {
        byte[]    data = new byte[2];
        
        data[0] = (byte)v1;
        data[1] = (byte)v2;
        
        return data;
    }
    
    public trustsignature(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.trust_sig, critical, data);
    }
    
    public trustsignature(
        boolean    critical,
        int        depth,
        int        trustamount)
    {
        super(signaturesubpackettags.trust_sig, critical, inttobytearray(depth, trustamount));
    }
    
    public int getdepth()
    {
        return data[0] & 0xff;
    }
    
    public int gettrustamount()
    {
        return data[1] & 0xff;
    }
}
