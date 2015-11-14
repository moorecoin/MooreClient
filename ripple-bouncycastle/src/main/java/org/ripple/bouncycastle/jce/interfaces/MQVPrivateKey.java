package org.ripple.bouncycastle.jce.interfaces;

import java.security.privatekey;
import java.security.publickey;

/**
 * static/ephemeral private key (pair) for use with ecmqv key agreement
 * (optionally provides the ephemeral public key)
 */
public interface mqvprivatekey
    extends privatekey
{
    /**
     * return the static private key.
     */
    privatekey getstaticprivatekey();

    /**
     * return the ephemeral private key.
     */
    privatekey getephemeralprivatekey();

    /**
     * return the ephemeral public key (may be null).
     */
    publickey getephemeralpublickey();
}
