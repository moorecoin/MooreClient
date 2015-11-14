package org.ripple.bouncycastle.bcpg.sig;

import java.util.date;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet giving signature creation time.
 */
public class signaturecreationtime 
    extends signaturesubpacket
{
    protected static byte[] timetobytes(
        date    date)
    {
        byte[]    data = new byte[4];
        long        t = date.gettime() / 1000;
        
        data[0] = (byte)(t >> 24);
        data[1] = (byte)(t >> 16);
        data[2] = (byte)(t >> 8);
        data[3] = (byte)t;
        
        return data;
    }
    
    public signaturecreationtime(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.creation_time, critical, data);
    }
    
    public signaturecreationtime(
        boolean    critical,
        date       date)
    {
        super(signaturesubpackettags.creation_time, critical, timetobytes(date));
    }
    
    public date gettime()
    {
        long    time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        
        return new date(time * 1000);
    }
}
