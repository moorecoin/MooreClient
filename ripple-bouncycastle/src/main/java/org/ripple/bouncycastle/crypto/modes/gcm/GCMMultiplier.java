package org.ripple.bouncycastle.crypto.modes.gcm;

public interface gcmmultiplier
{
    void init(byte[] h);
    void multiplyh(byte[] x);
}
