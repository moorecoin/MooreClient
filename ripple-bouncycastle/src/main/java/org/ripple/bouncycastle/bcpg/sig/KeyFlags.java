package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet holding the key flag values.
 */
public class keyflags 
    extends signaturesubpacket
{
    public static final int certify_other = 0x01;
    public static final int sign_data = 0x02;
    public static final int encrypt_comms = 0x04;
    public static final int encrypt_storage = 0x08;
    public static final int split = 0x10;
    public static final int authentication = 0x20;
    public static final int shared = 0x80;
    
    private static byte[] inttobytearray(
        int    v)
    {
        byte[] tmp = new byte[4];
        int    size = 0;

        for (int i = 0; i != 4; i++)
        {
            tmp[i] = (byte)(v >> (i * 8));
            if (tmp[i] != 0)
            {
                size = i;
            }
        }

        byte[]    data = new byte[size + 1];
        
        system.arraycopy(tmp, 0, data, 0, data.length);

        return data;
    }
    
    public keyflags(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.key_flags, critical, data);
    }
    
    public keyflags(
        boolean    critical,
        int        flags)
    {
        super(signaturesubpackettags.key_flags, critical, inttobytearray(flags));
    }

    /**
     * return the flag values contained in the first 4 octets (note: at the moment
     * the standard only uses the first one).
     *
     * @return flag values.
     */
    public int getflags()
    {
        int flags = 0;

        for (int i = 0; i != data.length; i++)
        {
            flags |= (data[i] & 0xff) << (i * 8);
        }

        return flags;
    }
}
