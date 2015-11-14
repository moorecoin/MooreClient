package org.ripple.bouncycastle.bcpg;

public class crc24
{
    private static final int crc24_init = 0x0b704ce;
    private static final int crc24_poly = 0x1864cfb;
                                                                                
    private int crc = crc24_init;
                                                                                
    public crc24()
    {
    }

    public void update(
        int b)
    {
        crc ^= b << 16;
        for (int i = 0; i < 8; i++)
        {
            crc <<= 1;
            if ((crc & 0x1000000) != 0)
            {
                crc ^= crc24_poly;
            }
        }
    }

    public int getvalue()
    {
        return crc;
    }

    public void reset()
    {
        crc = crc24_init;
    }
}
