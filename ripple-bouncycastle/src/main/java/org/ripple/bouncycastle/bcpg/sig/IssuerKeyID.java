package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet giving signature creation time.
 */
public class issuerkeyid 
    extends signaturesubpacket
{
    protected static byte[] keyidtobytes(
        long    keyid)
    {
        byte[]    data = new byte[8];
        
        data[0] = (byte)(keyid >> 56);
        data[1] = (byte)(keyid >> 48);
        data[2] = (byte)(keyid >> 40);
        data[3] = (byte)(keyid >> 32);
        data[4] = (byte)(keyid >> 24);
        data[5] = (byte)(keyid >> 16);
        data[6] = (byte)(keyid >> 8);
        data[7] = (byte)keyid;
        
        return data;
    }
    
    public issuerkeyid(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.issuer_key_id, critical, data);
    }
    
    public issuerkeyid(
        boolean    critical,
        long       keyid)
    {
        super(signaturesubpackettags.issuer_key_id, critical, keyidtobytes(keyid));
    }
    
    public long getkeyid()
    {
        long    keyid = ((long)(data[0] & 0xff) << 56) | ((long)(data[1] & 0xff) << 48) | ((long)(data[2] & 0xff) << 40) | ((long)(data[3] & 0xff) << 32)
                                | ((long)(data[4] & 0xff) << 24) | ((data[5] & 0xff) << 16) | ((data[6] & 0xff) << 8) | (data[7] & 0xff);
        
        return keyid;
    }
}
