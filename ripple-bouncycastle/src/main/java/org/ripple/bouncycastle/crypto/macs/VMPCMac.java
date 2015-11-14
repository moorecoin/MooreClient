package org.ripple.bouncycastle.crypto.macs;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;

public class vmpcmac implements mac
{
    private byte g;

    private byte n = 0;
    private byte[] p = null;
    private byte s = 0;

    private byte[] t;
    private byte[] workingiv;

    private byte[] workingkey;

    private byte x1, x2, x3, x4;

    public int dofinal(byte[] out, int outoff)
        throws datalengthexception, illegalstateexception
    {
        // execute the post-processing phase
        for (int r = 1; r < 25; r++)
        {
            s = p[(s + p[n & 0xff]) & 0xff];

            x4 = p[(x4 + x3 + r) & 0xff];
            x3 = p[(x3 + x2 + r) & 0xff];
            x2 = p[(x2 + x1 + r) & 0xff];
            x1 = p[(x1 + s + r) & 0xff];
            t[g & 0x1f] = (byte) (t[g & 0x1f] ^ x1);
            t[(g + 1) & 0x1f] = (byte) (t[(g + 1) & 0x1f] ^ x2);
            t[(g + 2) & 0x1f] = (byte) (t[(g + 2) & 0x1f] ^ x3);
            t[(g + 3) & 0x1f] = (byte) (t[(g + 3) & 0x1f] ^ x4);
            g = (byte) ((g + 4) & 0x1f);

            byte temp = p[n & 0xff];
            p[n & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
            n = (byte) ((n + 1) & 0xff);
        }

        // input t to the iv-phase of the vmpc ksa
        for (int m = 0; m < 768; m++)
        {
            s = p[(s + p[m & 0xff] + t[m & 0x1f]) & 0xff];
            byte temp = p[m & 0xff];
            p[m & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
        }

        // store 20 new outputs of the vmpc stream cipher in table m
        byte[] m = new byte[20];
        for (int i = 0; i < 20; i++)
        {
            s = p[(s + p[i & 0xff]) & 0xff];
            m[i] = p[(p[(p[s & 0xff]) & 0xff] + 1) & 0xff];

            byte temp = p[i & 0xff];
            p[i & 0xff] = p[s & 0xff];
            p[s & 0xff] = temp;
        }

        system.arraycopy(m, 0, out, outoff, m.length);
        reset();

        return m.length;
    }

    public string getalgorithmname()
    {
        return "vmpc-mac";
    }

    public int getmacsize()
    {
        return 20;
    }

    public void init(cipherparameters params) throws illegalargumentexception
    {
        if (!(params instanceof parameterswithiv))
        {
            throw new illegalargumentexception(
                "vmpc-mac init parameters must include an iv");
        }

        parameterswithiv ivparams = (parameterswithiv) params;
        keyparameter key = (keyparameter) ivparams.getparameters();

        if (!(ivparams.getparameters() instanceof keyparameter))
        {
            throw new illegalargumentexception(
                "vmpc-mac init parameters must include a key");
        }

        this.workingiv = ivparams.getiv();

        if (workingiv == null || workingiv.length < 1 || workingiv.length > 768)
        {
            throw new illegalargumentexception(
                "vmpc-mac requires 1 to 768 bytes of iv");
        }

        this.workingkey = key.getkey();

        reset();

    }

    private void initkey(byte[] keybytes, byte[] ivbytes)
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
        n = 0;
    }

    public void reset()
    {
        initkey(this.workingkey, this.workingiv);
        g = x1 = x2 = x3 = x4 = n = 0;
        t = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            t[i] = 0;
        }
    }

    public void update(byte in) throws illegalstateexception
    {
        s = p[(s + p[n & 0xff]) & 0xff];
        byte c = (byte) (in ^ p[(p[(p[s & 0xff]) & 0xff] + 1) & 0xff]);

        x4 = p[(x4 + x3) & 0xff];
        x3 = p[(x3 + x2) & 0xff];
        x2 = p[(x2 + x1) & 0xff];
        x1 = p[(x1 + s + c) & 0xff];
        t[g & 0x1f] = (byte) (t[g & 0x1f] ^ x1);
        t[(g + 1) & 0x1f] = (byte) (t[(g + 1) & 0x1f] ^ x2);
        t[(g + 2) & 0x1f] = (byte) (t[(g + 2) & 0x1f] ^ x3);
        t[(g + 3) & 0x1f] = (byte) (t[(g + 3) & 0x1f] ^ x4);
        g = (byte) ((g + 4) & 0x1f);

        byte temp = p[n & 0xff];
        p[n & 0xff] = p[s & 0xff];
        p[s & 0xff] = temp;
        n = (byte) ((n + 1) & 0xff);
    }

    public void update(byte[] in, int inoff, int len)
        throws datalengthexception, illegalstateexception
    {
        if ((inoff + len) > in.length)
        {
            throw new datalengthexception("input buffer too short");
        }

        for (int i = 0; i < len; i++)
        {
            update(in[i]);
        }
    }
}
