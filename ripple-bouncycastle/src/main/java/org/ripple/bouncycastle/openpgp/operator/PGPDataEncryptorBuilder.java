package org.ripple.bouncycastle.openpgp.operator;

import java.security.securerandom;

import org.ripple.bouncycastle.openpgp.pgpexception;

public interface pgpdataencryptorbuilder
{
    int getalgorithm();

    pgpdataencryptor build(byte[] keybytes)
        throws pgpexception;

    securerandom getsecurerandom();
}
