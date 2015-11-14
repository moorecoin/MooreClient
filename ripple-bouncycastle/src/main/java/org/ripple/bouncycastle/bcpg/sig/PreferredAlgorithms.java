package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;

/**
 * packet giving signature creation time.
 */
public class preferredalgorithms 
    extends signaturesubpacket
{    
    private static byte[] inttobytearray(
        int[]    v)
    {
        byte[]    data = new byte[v.length];
        
        for (int i = 0; i != v.length; i++)
        {
            data[i] = (byte)v[i];
        }
        
        return data;
    }
    
    public preferredalgorithms(
        int        type,
        boolean    critical,
        byte[]     data)
    {
        super(type, critical, data);
    }
    
    public preferredalgorithms(
        int        type,
        boolean    critical,
        int[]      preferrences)
    {
        super(type, critical, inttobytearray(preferrences));
    }
    
    /**
     * @deprecated mispelt!
     */
    public int[] getpreferrences()
    {
        return getpreferences();
    }

    public int[] getpreferences()
    {
        int[]    v = new int[data.length];
        
        for (int i = 0; i != v.length; i++)
        {
            v[i] = data[i] & 0xff;
        }
        
        return v;
    }
}
