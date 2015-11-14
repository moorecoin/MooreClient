package org.ripple.bouncycastle.crypto.modes.gcm;

import org.ripple.bouncycastle.util.arrays;

public class basicgcmmultiplier implements gcmmultiplier
{
    private byte[] h;

    public void init(byte[] h)
    {
        this.h = arrays.clone(h);
    }

    public void multiplyh(byte[] x)
    {
        gcmutil.multiply(x, h);
    }
}
