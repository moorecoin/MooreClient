package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public interface tlsencryptioncredentials
    extends tlscredentials
{

    byte[] decryptpremastersecret(byte[] encryptedpremastersecret)
        throws ioexception;
}
