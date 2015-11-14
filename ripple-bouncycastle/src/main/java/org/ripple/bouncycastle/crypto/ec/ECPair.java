package org.ripple.bouncycastle.crypto.ec;

import org.ripple.bouncycastle.math.ec.ecpoint;

public class ecpair
{
    private final ecpoint x;
    private final ecpoint y;

    public ecpair(ecpoint x, ecpoint y)
    {
        this.x = x;
        this.y = y;
    }

    public ecpoint getx()
    {
        return x;
    }

    public ecpoint gety()
    {
        return y;
    }

    public byte[] getencoded()
    {
        byte[] xenc = x.getencoded();
        byte[] yenc = y.getencoded();

        byte[] full = new byte[xenc.length + yenc.length];

        system.arraycopy(xenc, 0, full, 0, xenc.length);
        system.arraycopy(yenc, 0, full, xenc.length, yenc.length);

        return full;
    }
}
