package org.ripple.bouncycastle.crypto.engines;

public class vmpcksa3engine extends vmpcengine
{
    public string getalgorithmname()
    {
        return "vmpc-ksa3";
    }

    protected void initkey(byte[] keybytes, byte[] ivbytes)
    {
        s = 0;
        p = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            p[i] = (byte) i;
        }

        for (int m = 0; m < 768; m++)
        {
            s = p[(s + p[m & 0xff] + keybytes[m % keybytes.length]) & 0xff];
            byte temp = p[m & 0xff];
            p[m & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
        }

        for (int m = 0; m < 768; m++)
        {
            s = p[(s + p[m & 0xff] + ivbytes[m % ivbytes.length]) & 0xff];
            byte temp = p[m & 0xff];
            p[m & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
        }

        for (int m = 0; m < 768; m++)
        {
            s = p[(s + p[m & 0xff] + keybytes[m % keybytes.length]) & 0xff];
            byte temp = p[m & 0xff];
            p[m & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
        }

        n = 0;
    }
}
