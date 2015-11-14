package org.ripple.bouncycastle.jce.interfaces;

import java.security.publickey;

/**
 * static/ephemeral public key pair for use with ecmqv key agreement
 */
public interface mqvpublickey
    extends publickey
{
    /**
     * return the static public key.
     */
    publickey getstatickey();

    /**
     * return the ephemeral public key.
     */
    publickey getephemeralkey();
}
