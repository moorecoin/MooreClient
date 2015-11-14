package org.ripple.bouncycastle.jce.interfaces;

import java.security.key;
import java.security.privatekey;
import java.security.publickey;

/**
 * key pair for use with an integrated encryptor
 */
public interface ieskey
    extends key
{
    /**
     * return the intended recipient's/sender's public key.
     */
    public publickey getpublic();

    /**
     * return the local private key.
     */
    public privatekey getprivate();
}
