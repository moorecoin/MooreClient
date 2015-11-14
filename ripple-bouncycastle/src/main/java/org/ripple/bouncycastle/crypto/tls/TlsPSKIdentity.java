package org.ripple.bouncycastle.crypto.tls;

public interface tlspskidentity
{
    void skipidentityhint();

    void notifyidentityhint(byte[] psk_identity_hint);

    byte[] getpskidentity();

    byte[] getpsk();
}
