package org.ripple.bouncycastle.crypto.modes.gcm;

public interface gcmexponentiator
{
    void init(byte[] x);
    void exponentiatex(long pow, byte[] output);
}
