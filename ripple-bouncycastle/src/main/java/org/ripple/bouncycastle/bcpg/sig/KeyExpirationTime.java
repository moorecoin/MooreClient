package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet giving time after creation at which the key expires.
 */
public class keyexpirationtime 
    extends signaturesubpacket
{
    protected static byte[] timetobytes(
        long    t)
    {
        byte[]    data = new byte[4];
        
        data[0] = (byte)(t >> 24);
        data[1] = (byte)(t >> 16);
        data[2] = (byte)(t >> 8);
        data[3] = (byte)t;
        
        return data;
    }
    
    public keyexpirationtime(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.key_expire_time, critical, data);
    }
    
    public keyexpirationtime(
        boolean    critical,
        long       seconds)
    {
        super(signaturesubpackettags.key_expire_time, critical, timetobytes(seconds));
    }
    
    /**
     * return the number of seconds after creation time a key is valid for.
     * 
     * @return second count for key validity.
     */
    public long gettime()
    {
        long    time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        
        return time;
    }
}
